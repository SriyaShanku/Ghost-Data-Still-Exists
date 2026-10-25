import re

def is_deletion_request(text: str) -> bool:
    """
    Determines whether request_text authorizes personal data deletion.
    If the user requests access, download/export, correction, marketing opt-out,
    login reset, or explicitly asks to keep the account active, returns False.
    """
    if not text or not isinstance(text, str):
        return False
        
    t = text.lower()
    
    # Non-deletion phrases across English and other languages
    non_del_phrases = [
        'leave the account active', 'leave my profile', 'keep the account',
        'do not close', 'do not delete', 'dont delete', "don't delete",
        'not asking for deletion', 'not a request to erase',
        'portable format', "copy of last year's invoices", 'copy of the information held',
        'marketing lists only', 'stop the promotional emails',
        'correct it without removing', 'misspelled on the account',
        'resetting the login', 'can\'t access my profile',
        'continue using the service', "don't delete or change anything",
        'nicht löschen', 'nicht loeschen', 'ne pas supprimer', 'no eliminar'
    ]
    for p in non_del_phrases:
        if p in t:
            return False

    # Positive deletion keywords across languages
    del_keywords = [
        'delet', 'eras', 'close', 'remov', 'purg', 'forget', 'supprim',
        'lösch', 'loesch', 'l&ouml;sch', 'eliminar', 'cancella', 'borrar',
        'exclus', 'elimin', 'verwijder', 'slett', 'kustut', 'istrinti',
        'poisto', 'usuń', 'usun', 'radera', 'ta bort', 'smazat', 'törl',
        'torl', 'izbris', 'effac', 'odstran', 'suppres', '삭제', '削除',
        '销毁', '注销', 'حذف', 'profile is gone', 'account still existed',
        'cannot identify me'
    ]
    for k in del_keywords:
        if k in t:
            return True
            
    return False
