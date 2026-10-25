import os
import sys
import json
import sqlite3
import argparse
import pandas as pd
from datetime import datetime

# Local imports
from identity import IdentityResolver
from intent import is_deletion_request

OP_ORDER = {
    'FINDING': {
        'REPORT_REMAINING_RECORD': 1,
        'REPORT_EXPOSED_PII': 2,
        'REPORT_ACTIVE_DATA_FLOW': 3,
        'REPORT_RESTORE_RISK': 4
    },
    'REMEDIATION': {
        'DISABLE_DATA_FLOW': 1,
        'BLOCK_RESTORE': 2,
        'DELETE_RECORD': 3,
        'REDACT_RECORD': 4,
        'ANONYMIZE_RECORD': 5
    },
    'VERIFICATION': {
        'VERIFY_RECORD_ABSENT': 1,
        'VERIFY_RECORD_PRESENT': 2,
        'VERIFY_RECORD_REDACTED': 3,
        'VERIFY_RECORD_ANONYMIZED': 4,
        'VERIFY_DATA_FLOW_DISABLED': 5,
        'VERIFY_RESTORE_BLOCKED': 6
    }
}

PHASE_ORDER = {
    'FINDING': 1,
    'REMEDIATION': 2,
    'VERIFICATION': 3
}

SYS_MAP = {
    'account': 'account_service',
    'search': 'search_service',
    'analytics': 'analytics_platform',
    'support': 'support_platform',
    'export': 'export_service',
    'data_flow': 'integration_service',
    'backup': 'backup_service',
    'audit_record': 'security_service',
    'tombstone': 'identity_service'
}

def get_system_id(res_id: str) -> str:
    p = res_id.split('_')[0]
    if p in ['data', 'audit']:
        p = '_'.join(res_id.split('_')[:2])
    return SYS_MAP.get(p, 'account_service')


class EvidenceScanner:
    def __init__(self, dataset_dir: str):
        self.dataset_dir = dataset_dir
        self.ev_manifest = pd.read_csv(os.path.join(dataset_dir, 'evidence_files.csv'))
        self.activity_df = pd.read_csv(os.path.join(dataset_dir, 'system_activity.csv'))
        
        # Sort evidence by capture time
        self.ev_manifest['captured_at_dt'] = pd.to_datetime(self.ev_manifest['captured_at'])
        self.ev_manifest = self.ev_manifest.sort_values('captured_at_dt')
        
        # In-memory index of evidence records: res_id -> list of records
        self.evidence_records = {} # res_id -> [(file_id, captured_at, status_dict)]
        self.user_to_resources = {} # uid -> set of res_ids
        self.email_to_resources = {} # email -> set of res_ids
        
        self._load_evidence()
        self._index_activity()

    def _load_evidence(self):
        for _, ef in self.ev_manifest.iterrows():
            fid = ef['file_id']
            fpath = os.path.join(self.dataset_dir, ef['file_path'])
            if not os.path.exists(fpath):
                continue
            ext = os.path.splitext(fpath)[1].lower()
            cap = ef['captured_at']
            
            if ext == '.json':
                self._parse_json(fid, cap, fpath)
            elif ext == '.sql':
                self._parse_sql(fid, cap, fpath)
            elif ext in ['.log', '.txt']:
                self._parse_text(fid, cap, fpath)

    def _add_rec(self, fid: str, cap: str, res_id: str, rec: dict):
        if not res_id:
            return
        if res_id not in self.evidence_records:
            self.evidence_records[res_id] = []
        self.evidence_records[res_id].append((fid, cap, rec))
        
        # Associate with user/email
        for k in ['customer_reference', 'user_id', 'subject_reference']:
            v = rec.get(k)
            if v and isinstance(v, str):
                uid = v.strip()
                if uid not in self.user_to_resources:
                    self.user_to_resources[uid] = set()
                self.user_to_resources[uid].add(res_id)
                
        for k in ['email', 'owner_email', 'requester_email', 'customer_email', 'lookup_key']:
            v = rec.get(k)
            if v and isinstance(v, str) and '@' in v:
                em = v.strip().lower()
                if em not in self.email_to_resources:
                    self.email_to_resources[em] = set()
                self.email_to_resources[em].add(res_id)

    def _parse_json(self, fid: str, cap: str, fpath: str):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            
            def walk(obj):
                if isinstance(obj, dict):
                    res_id = obj.get('resource_id')
                    if res_id and isinstance(res_id, str):
                        self._add_rec(fid, cap, res_id, obj)
                    for k, v in obj.items():
                        walk(v)
                elif isinstance(obj, list):
                    for item in obj:
                        walk(item)
            walk(data)
        except Exception:
            pass

    def _parse_sql(self, fid: str, cap: str, fpath: str):
        try:
            conn = sqlite3.connect(':memory:')
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                conn.executescript(f.read())
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [r[0] for r in cur.fetchall()]
            for t in tables:
                cur.execute(f"PRAGMA table_info({t});")
                cols = [c[1] for c in cur.fetchall()]
                if 'resource_id' in cols:
                    cur.execute(f"SELECT * FROM {t};")
                    for row in cur.fetchall():
                        d = dict(zip(cols, row))
                        res_id = d.get('resource_id')
                        if res_id:
                            self._add_rec(fid, cap, res_id, d)
            conn.close()
        except Exception:
            pass

    def _parse_text(self, fid: str, cap: str, fpath: str):
        import re
        try:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_s = line.strip()
                    if '|' in line_s and not line_s.startswith('#'):
                        parts = [p.strip() for p in line_s.split('|')]
                        if len(parts) >= 6:
                            ts = parts[0].lstrip('- ')
                            sys_n = parts[1]
                            res_id = parts[2]
                            cat = parts[3]
                            status_val = parts[4]
                            ident_val = parts[5]
                            d = {
                                'resource_id': res_id,
                                'system': sys_n,
                                'category': cat,
                                'status_val': status_val,
                                'observed_at': ts
                            }
                            if '@' in ident_val:
                                d['email'] = ident_val
                            elif 'user_' in ident_val:
                                d['user_id'] = ident_val
                            self._add_rec(fid, cap, res_id, d)
                            continue
                    
                    if 'resource_id' in line or '=' in line:
                        matches = re.findall(r'(\w+)=(?:"([^"]*)"|(\S+))', line)
                        if matches:
                            d = {}
                            for k, v1, v2 in matches:
                                d[k] = v1 if v1 else v2
                            res_id = d.get('resource_id')
                            if res_id:
                                for k in ['match_key', 'subject_key', 'lookup_key', 'correlation_key', 'matched_value', 'owner_email', 'requester_email']:
                                    val = d.get(k)
                                    if val and '@' in val:
                                        d['email'] = val
                                for k in ['subject_ref', 'user_id', 'customer_reference']:
                                    val = d.get(k)
                                    if val and 'user_' in val:
                                        d['user_id'] = val
                                self._add_rec(fid, cap, res_id, d)
        except Exception:
            pass

    def _index_activity(self):
        # Index activities by resource_id
        self.activity_by_res = {}
        for _, a in self.activity_df.iterrows():
            res_id = a['resource_id']
            if pd.notna(res_id):
                if res_id not in self.activity_by_res:
                    self.activity_by_res[res_id] = []
                self.activity_by_res[res_id].append(a.to_dict())


def audit_case(row, identity_resolver: IdentityResolver, scanner: EvidenceScanner) -> tuple:
    cid = row['case_id']
    req_email = str(row['email']).strip().lower()
    req_text = str(row['request_text'])
    audit_at = str(row['audit_at'])
    req_at = str(row['requested_at'])
    rep_at = str(row['reported_at'])
    
    # 1. Intent check
    if not is_deletion_request(req_text):
        return (cid, "NOT_APPLICABLE", [])

    # 2. Identity resolution
    uid = identity_resolver.resolve_email(req_email)
    user_info = identity_resolver.get_user_info(uid) if uid else None
    
    user_emails = user_info['emails'] if user_info else {req_email}
    user_phones = user_info['phones'] if user_info else set()
    user_names = user_info['names'] if user_info else set()
    user_hashes = user_info['hashes'] if user_info else set()

    # 3. Find candidate resources
    candidate_res = set()
    if uid and uid in scanner.user_to_resources:
        candidate_res.update(scanner.user_to_resources[uid])
    for em in user_emails:
        if em in scanner.email_to_resources:
            candidate_res.update(scanner.email_to_resources[em])
            
    # Also find activities in deletion workflow window for candidate resources
    sub_act = scanner.activity_df[
        (scanner.activity_df['event_time'] >= req_at) & 
        (scanner.activity_df['event_time'] <= rep_at + 'Z') &
        (scanner.activity_df['source_system'] == 'deletion_worker')
    ]
    
    # Ensure account_XXXX from deletion workflow is included
    if not any(get_system_id(r) == 'account_service' for r in candidate_res):
        for _, a in sub_act.iterrows():
            if a['target_system'] == 'account_service' and str(a['resource_id']).startswith('account_'):
                candidate_res.add(a['resource_id'])
                break
    
    # If no candidate resources found via direct email/uid lookup, match activities
    # Find latest evidence snapshot at or before audit_at
    valid_evs = scanner.ev_manifest[scanner.ev_manifest['captured_at'] <= audit_at].sort_values('captured_at', ascending=False)
    default_ev_id = valid_evs.iloc[0]['file_id'] if len(valid_evs) > 0 else 'evidence_01'
    
    # Check if there's an evidence file specifically matching this user
    user_ev_id = default_ev_id
    for fid in valid_evs['file_id']:
        # If this fid has records for this user
        matched = False
        for r in candidate_res:
            records = scanner.evidence_records.get(r, [])
            for efid, cap, rec in records:
                if efid == fid:
                    user_ev_id = fid
                    matched = True
                    break
            if matched:
                break
        if matched:
            break

    findings = []
    remediations = []
    verifications = []
    
    # Helper to determine resource status
    # Check each candidate resource
    for res_id in sorted(list(candidate_res)):
        sys_id = get_system_id(res_id)
        records = scanner.evidence_records.get(res_id, [])
        valid_records = [r for r in records if r[1] <= audit_at]
        latest_rec = valid_records[-1] if valid_records else None
        
        evidence_id = latest_rec[0] if latest_rec else user_ev_id
        rec_data = latest_rec[2] if latest_rec else {}
        
        # Check system type
        if sys_id == 'account_service':
            # Check if account still active or failed deletion
            is_active = False
            status = rec_data.get('account_status')
            if status == 'ACTIVE':
                is_active = True
            elif rec_data.get('status_code') == 404 or rec_data.get('profile') is None:
                is_active = False
            else:
                # check activity claims
                acts = scanner.activity_by_res.get(res_id, [])
                for a in acts:
                    if a['event_time'] <= audit_at and a['event_type'] == 'DELETE_RECORD' and a['reported_result'] in ['FAILED', 'PARTIAL']:
                        is_active = True
                        
            if is_active:
                findings.append({
                    'phase': 'FINDING',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'REPORT_REMAINING_RECORD',
                    'state': 'PRESENT',
                    'evidence_id': evidence_id
                })
                remediations.append({
                    'phase': 'REMEDIATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'DELETE_RECORD',
                    'state': 'ABSENT',
                    'evidence_id': ''
                })
                verifications.append({
                    'phase': 'VERIFICATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'VERIFY_RECORD_ABSENT',
                    'state': 'ABSENT',
                    'evidence_id': ''
                })
            else:
                verifications.append({
                    'phase': 'VERIFICATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'VERIFY_RECORD_ABSENT',
                    'state': 'ABSENT',
                    'evidence_id': evidence_id
                })

        elif sys_id == 'search_service':
            is_present = False
            # If search document exists or query returned hit
            if 'hits' in rec_data:
                hits = rec_data['hits']
                if isinstance(hits, dict) and hits.get('total', 0) > 0:
                    is_present = True
            elif 'document' in rec_data or 'email' in rec_data:
                is_present = True
                
            acts = scanner.activity_by_res.get(res_id, [])
            for a in acts:
                if a['event_time'] <= audit_at and a['event_type'] == 'DELETE_RECORD' and a['reported_result'] in ['FAILED', 'PARTIAL']:
                    is_present = True
                    
            if is_present:
                findings.append({
                    'phase': 'FINDING',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'REPORT_REMAINING_RECORD',
                    'state': 'PRESENT',
                    'evidence_id': evidence_id
                })
                remediations.append({
                    'phase': 'REMEDIATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'DELETE_RECORD',
                    'state': 'ABSENT',
                    'evidence_id': ''
                })
                verifications.append({
                    'phase': 'VERIFICATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'VERIFY_RECORD_ABSENT',
                    'state': 'ABSENT',
                    'evidence_id': ''
                })
            else:
                verifications.append({
                    'phase': 'VERIFICATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'VERIFY_RECORD_ABSENT',
                    'state': 'ABSENT',
                    'evidence_id': evidence_id
                })

        elif sys_id == 'export_service':
            is_present = bool(rec_data.get('object_key') or rec_data.get('owner_email'))
            acts = scanner.activity_by_res.get(res_id, [])
            for a in acts:
                if a['event_time'] <= audit_at and a['event_type'] == 'DELETE_RECORD' and a['reported_result'] in ['FAILED', 'PARTIAL']:
                    is_present = True
            if is_present:
                findings.append({
                    'phase': 'FINDING',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'REPORT_REMAINING_RECORD',
                    'state': 'PRESENT',
                    'evidence_id': evidence_id
                })
                remediations.append({
                    'phase': 'REMEDIATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'DELETE_RECORD',
                    'state': 'ABSENT',
                    'evidence_id': ''
                })
                verifications.append({
                    'phase': 'VERIFICATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'VERIFY_RECORD_ABSENT',
                    'state': 'ABSENT',
                    'evidence_id': ''
                })
            else:
                verifications.append({
                    'phase': 'VERIFICATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'VERIFY_RECORD_ABSENT',
                    'state': 'ABSENT',
                    'evidence_id': evidence_id
                })

        elif sys_id == 'support_platform':
            # Check if exposed PII or deleted
            msg = str(rec_data.get('message_text') or rec_data.get('message_excerpt') or '')
            req_em = rec_data.get('requester_email')
            has_pii = bool(req_em or any(em in msg.lower() for em in user_emails))
            acts = scanner.activity_by_res.get(res_id, [])
            for a in acts:
                if a['event_time'] <= audit_at and a['event_type'] == 'REDACT_RECORD' and a['reported_result'] in ['FAILED', 'PARTIAL']:
                    has_pii = True
            if has_pii:
                findings.append({
                    'phase': 'FINDING',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'REPORT_EXPOSED_PII',
                    'state': 'PRESENT',
                    'evidence_id': evidence_id
                })
                remediations.append({
                    'phase': 'REMEDIATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'REDACT_RECORD',
                    'state': 'REDACTED',
                    'evidence_id': ''
                })
                verifications.append({
                    'phase': 'VERIFICATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'VERIFY_RECORD_REDACTED',
                    'state': 'REDACTED',
                    'evidence_id': ''
                })
            else:
                verifications.append({
                    'phase': 'VERIFICATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'VERIFY_RECORD_REDACTED',
                    'state': 'REDACTED',
                    'evidence_id': evidence_id
                })

        elif sys_id == 'analytics_platform':
            em = rec_data.get('email')
            has_pii = bool(em or rec_data.get('phone') or rec_data.get('email_hash'))
            acts = scanner.activity_by_res.get(res_id, [])
            for a in acts:
                if a['event_time'] <= audit_at and a['event_type'] == 'ANONYMIZE_RECORD' and a['reported_result'] in ['FAILED', 'PARTIAL']:
                    has_pii = True
            if has_pii:
                findings.append({
                    'phase': 'FINDING',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'REPORT_EXPOSED_PII',
                    'state': 'PRESENT',
                    'evidence_id': evidence_id
                })
                remediations.append({
                    'phase': 'REMEDIATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'ANONYMIZE_RECORD',
                    'state': 'ANONYMIZED',
                    'evidence_id': ''
                })
                verifications.append({
                    'phase': 'VERIFICATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'VERIFY_RECORD_ANONYMIZED',
                    'state': 'ANONYMIZED',
                    'evidence_id': ''
                })
            else:
                verifications.append({
                    'phase': 'VERIFICATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'VERIFY_RECORD_ANONYMIZED',
                    'state': 'ANONYMIZED',
                    'evidence_id': evidence_id
                })

        elif sys_id == 'integration_service':
            is_enabled = bool(rec_data.get('enabled', True))
            acts = scanner.activity_by_res.get(res_id, [])
            for a in acts:
                if a['event_time'] <= audit_at and a['event_type'] == 'CHECK_DATA_FLOW' and a['reported_result'] == 'SUCCESS':
                    is_enabled = True
                elif a['event_time'] <= audit_at and a['event_type'] == 'DISABLE_DATA_FLOW' and a['reported_result'] == 'SUCCESS':
                    is_enabled = False
            if is_enabled:
                findings.append({
                    'phase': 'FINDING',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'REPORT_ACTIVE_DATA_FLOW',
                    'state': 'ACTIVE',
                    'evidence_id': evidence_id
                })
                remediations.append({
                    'phase': 'REMEDIATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'DISABLE_DATA_FLOW',
                    'state': 'DISABLED',
                    'evidence_id': ''
                })
                verifications.append({
                    'phase': 'VERIFICATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'VERIFY_DATA_FLOW_DISABLED',
                    'state': 'DISABLED',
                    'evidence_id': ''
                })
            else:
                verifications.append({
                    'phase': 'VERIFICATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'VERIFY_DATA_FLOW_DISABLED',
                    'state': 'DISABLED',
                    'evidence_id': evidence_id
                })

        elif sys_id == 'backup_service':
            restore_allowed = bool(rec_data.get('restore_allowed', False))
            acts = scanner.activity_by_res.get(res_id, [])
            for a in acts:
                if a['event_time'] <= audit_at and a['event_type'] in ['CHECK_RESTORE_ACCESS', 'RESTORE_BACKUP']:
                    restore_allowed = True
                elif a['event_time'] <= audit_at and a['event_type'] == 'BLOCK_RESTORE' and a['reported_result'] == 'SUCCESS':
                    restore_allowed = False
            if restore_allowed:
                findings.append({
                    'phase': 'FINDING',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'REPORT_RESTORE_RISK',
                    'state': 'ACTIVE',
                    'evidence_id': evidence_id
                })
                remediations.append({
                    'phase': 'REMEDIATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'BLOCK_RESTORE',
                    'state': 'BLOCKED',
                    'evidence_id': ''
                })
                verifications.append({
                    'phase': 'VERIFICATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'VERIFY_RESTORE_BLOCKED',
                    'state': 'BLOCKED',
                    'evidence_id': ''
                })
            else:
                verifications.append({
                    'phase': 'VERIFICATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'VERIFY_RESTORE_BLOCKED',
                    'state': 'BLOCKED',
                    'evidence_id': evidence_id
                })

        elif sys_id == 'identity_service': # tombstone
            has_pii = bool(rec_data.get('email') or rec_data.get('name') or rec_data.get('phone') or rec_data.get('email_hash'))
            acts = scanner.activity_by_res.get(res_id, [])
            for a in acts:
                if a['event_time'] <= audit_at and a['event_type'] == 'REDACT_RECORD' and a['reported_result'] in ['FAILED', 'PARTIAL']:
                    has_pii = True
            if has_pii:
                findings.append({
                    'phase': 'FINDING',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'REPORT_EXPOSED_PII',
                    'state': 'PRESENT',
                    'evidence_id': evidence_id
                })
                remediations.append({
                    'phase': 'REMEDIATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'REDACT_RECORD',
                    'state': 'REDACTED',
                    'evidence_id': ''
                })
                verifications.append({
                    'phase': 'VERIFICATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'VERIFY_RECORD_REDACTED',
                    'state': 'REDACTED',
                    'evidence_id': ''
                })
            else:
                verifications.append({
                    'phase': 'VERIFICATION',
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'VERIFY_RECORD_REDACTED',
                    'state': 'REDACTED',
                    'evidence_id': evidence_id
                })

        elif sys_id == 'security_service': # audit_record
            verifications.append({
                'phase': 'VERIFICATION',
                'system_id': sys_id,
                'resource_id': res_id,
                'operation': 'VERIFY_RECORD_PRESENT',
                'state': 'PRESENT',
                'evidence_id': evidence_id
            })

    # If there are findings, deletion is INCOMPLETE
    if len(findings) > 0:
        status = "INCOMPLETE"
        # Post-remediation verifications have evidence_id = ""
        for v in verifications:
            v['evidence_id'] = ''
        all_steps = findings + remediations + verifications
    else:
        status = "COMPLETE"
        # In COMPLETE cases, only verifications, each with evidence_id proving compliant state
        for v in verifications:
            if not v['evidence_id']:
                v['evidence_id'] = user_ev_id
        all_steps = verifications

    # Order all steps
    def step_sort_key(step):
        phase_k = PHASE_ORDER.get(step['phase'], 99)
        op_k = OP_ORDER.get(step['phase'], {}).get(step['operation'], 99)
        sys_k = step['system_id']
        res_k = step['resource_id']
        return (phase_k, op_k, sys_k, res_k)

    sorted_steps = sorted(all_steps, key=step_sort_key)
    
    # Assign consecutive 1-indexed step_no
    final_steps = []
    for idx, s in enumerate(sorted_steps, 1):
        step_dict = {
            'step_no': idx,
            'phase': s['phase'],
            'system_id': s['system_id'],
            'resource_id': s['resource_id'],
            'operation': s['operation'],
            'state': s['state'],
            'evidence_id': s['evidence_id']
        }
        final_steps.append(step_dict)

    return (cid, status, final_steps)


def run_pipeline(dataset_dir: str, input_csv: str, output_csv: str):
    print(f"Initializing audit pipeline with dataset at: {dataset_dir}")
    identity_resolver = IdentityResolver(
        os.path.join(dataset_dir, 'user_identities.csv'),
        os.path.join(dataset_dir, 'user_audit_log.csv')
    )
    scanner = EvidenceScanner(dataset_dir)
    
    print(f"Reading requests from: {input_csv}")
    requests_df = pd.read_csv(input_csv)
    
    results = []
    for _, row in requests_df.iterrows():
        cid, status, steps = audit_case(row, identity_resolver, scanner)
        steps_json = json.dumps(steps, separators=(',', ':'))
        results.append({
            'case_id': cid,
            'deletion_status': status,
            'steps_json': steps_json
        })
        
    out_df = pd.DataFrame(results)
    out_df = out_df.sort_values('case_id')
    out_df.to_csv(output_csv, index=False, columns=['case_id', 'deletion_status', 'steps_json'])
    print(f"Successfully generated {len(out_df)} predictions to {output_csv}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists Deletion Audit Agent")
    parser.add_argument('--dataset', default='dataset', help='Path to dataset directory')
    parser.add_argument('--input', default='dataset/deletion_requests.csv', help='Input requests CSV')
    parser.add_argument('--output', default='output.csv', help='Output CSV path')
    
    args = parser.parse_args()
    run_pipeline(args.dataset, args.input, args.output)
