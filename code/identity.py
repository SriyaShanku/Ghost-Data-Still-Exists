import hashlib
import pandas as pd
from typing import Dict, Any, Optional

def compute_email_hash(email: str) -> str:
    normalized = email.strip().lower().encode('utf-8')
    return hashlib.sha256(normalized).hexdigest()

class IdentityResolver:
    def __init__(self, identities_csv_path: str, audit_log_csv_path: str):
        self.users_df = pd.read_csv(identities_csv_path)
        self.audit_df = pd.read_csv(audit_log_csv_path)
        
        self.user_map: Dict[str, Dict[str, Any]] = {}
        self.email_to_uid: Dict[str, str] = {}
        
        self._build_identities()
        
    def _build_identities(self):
        for _, u in self.users_df.iterrows():
            uid = str(u['user_id']).strip()
            name = str(u['name']).strip() if pd.notna(u['name']) else ''
            email = str(u['email']).strip().lower() if pd.notna(u['email']) else ''
            phone = str(u['phone']).strip() if pd.notna(u['phone']) else ''
            ehash = str(u['email_hash']).strip().lower() if pd.notna(u['email_hash']) else ''
            
            if not ehash and email:
                ehash = compute_email_hash(email)
                
            self.user_map[uid] = {
                'user_id': uid,
                'names': {name.lower()} if name else set(),
                'emails': {email} if email else set(),
                'phones': {phone} if phone else set(),
                'hashes': {ehash} if ehash else set()
            }
            if email:
                self.email_to_uid[email] = uid

        # Process audit log for historical identifiers
        for _, a in self.audit_df.iterrows():
            uid = str(a['user_id']).strip()
            if uid not in self.user_map:
                continue
                
            field = str(a['field_name']).strip().lower()
            old_val = str(a['old_value']).strip() if pd.notna(a['old_value']) else ''
            new_val = str(a['new_value']).strip() if pd.notna(a['new_value']) else ''
            
            if field == 'email':
                for val in [old_val, new_val]:
                    if val:
                        v_lower = val.lower()
                        self.user_map[uid]['emails'].add(v_lower)
                        self.user_map[uid]['hashes'].add(compute_email_hash(v_lower))
                        if v_lower not in self.email_to_uid:
                            self.email_to_uid[v_lower] = uid
            elif field == 'phone':
                for val in [old_val, new_val]:
                    if val:
                        self.user_map[uid]['phones'].add(val)
            elif field == 'name':
                for val in [old_val, new_val]:
                    if val:
                        self.user_map[uid]['names'].add(val.lower())
                        
    def resolve_email(self, email: str) -> Optional[str]:
        if not email:
            return None
        return self.email_to_uid.get(email.strip().lower())
        
    def get_user_info(self, uid: str) -> Optional[Dict[str, Any]]:
        return self.user_map.get(uid)
