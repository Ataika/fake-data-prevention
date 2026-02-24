
"""
Multi-Party Signature Chain
Автор: Атай (UniMe System Security 2026)

Реализация цепочки подписей: Alice → Bob → Charlie
Каждый участник добавляет свою подпись поверх предыдущих

Это как документ который идёт через отделы:
1. Alice подписывает транзакцию
2. Bob получает, проверяет подпись Alice, добавляет свою
3. Charlie получает, проверяет обе подписи (Alice И Bob)

В реальном мире используется в:
- Multi-sig кошельках Bitcoin
- Документооборот с несколькими утверждающими
- Blockchain supply chain tracking
"""

import hashlib
import hmac
import json
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

# Симулируем разные секретные ключи для каждого участника
PARTY_KEYS = {
    'Alice': 'alice-secret-key-2026',
    'Bob': 'bob-secret-key-2026', 
    'Charlie': 'charlie-secret-key-2026'
}

@dataclass
class Signature:
    """
    One sign in chain
    """
    party: str          # who signed
    timestamp: str      #  when it signed
    signature: str      # sign (HMAC)
    prev_hash: str      # hash of the previous state ( chain complexity)

@dataclass
class SignatureChain:
    """
    Chain of the signes for one transaction
    """
    tx_id: str
    original_data: dict
    signatures: List[Signature]
    
    def to_dict(self):
        """Convert in dict for JSON"""
        return {
            'tx_id': self.tx_id,
            'original_data': self.original_data,
            'signatures': [asdict(s) for s in self.signatures]
        }

class MultiPartyProtocol:
    """
    Protocol for multi-party signings
    """
    
    def __init__(self):
        self.chains: Dict[str, SignatureChain] = {}  # tx_id -> chain
    
    def _compute_data_hash(self, data: dict) -> str:
        """
        Хэшируем данные транзакции
        Используем canonical JSON для детерминизма
        """
        canonical = json.dumps(data, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()
    
    def _sign_with_hmac(self, message: str, party: str) -> str:
        """
        Подписываем сообщение HMAC с ключом участника
        В реальности использовался бы RSA или ECDSA
        """
        key = PARTY_KEYS.get(party)
        if not key:
            raise ValueError(f"Unknown party: {party}")
        
        return hmac.new(
            key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def _verify_signature(self, message: str, signature: str, party: str) -> bool:
        """Check the sign"""
        expected = self._sign_with_hmac(message, party)
        return hmac.compare_digest(expected, signature)
    
    def initiate_chain(self, tx_data: dict, initiator: str = 'Alice') -> SignatureChain:
        """
        Шаг 1: Alice инициирует цепочку
        Подписывает оригинальные данные транзакции
        
        Args:
            tx_data: словарь с данными транзакции
            initiator: кто начинает цепочку (обычно Alice)
        
        Returns:
            SignatureChain с первой подписью
        """
        tx_id = tx_data.get('tx_id')
        if not tx_id:
            raise ValueError("Transaction must have tx_id")
        
        # Хэшируем оригинальные данные
        data_hash = self._compute_data_hash(tx_data)
        
        # Alice подписывает хэш
        signature_value = self._sign_with_hmac(data_hash, initiator)
        
        # Создаём первую подпись в цепи
        sig = Signature(
            party=initiator,
            timestamp=datetime.now(timezone.utc).isoformat(),
            signature=signature_value,
            prev_hash='0' * 64  # genesis signature, if there isnt hash before
        )
        
        # creating chain
        chain = SignatureChain(
            tx_id=tx_id,
            original_data=tx_data,
            signatures=[sig]
        )
        
        # save
        self.chains[tx_id] = chain
        
        return chain
    
    def add_signature(self, tx_id: str, party: str) -> bool:
        """
        Шаг 2-N: Следующий участник добавляет свою подпись
        
        Процесс:
        1. Получаем текущую цепочку
        2. Проверяем все предыдущие подписи
        3. Если валидны — добавляем свою подпись поверх
        
        Args:
            tx_id: ID транзакции
            party: кто подписывает (Bob, Charlie, etc)
        
        Returns:
            True если подпись добавлена, False если ошибка
        """
        # Получаем существующую цепочку
        chain = self.chains.get(tx_id)
        if not chain:
            print(f"ERROR: Chain for {tx_id} not found")
            return False
        
        # Проверяем что этот участник ещё не подписывал
        existing_parties = [s.party for s in chain.signatures]
        if party in existing_parties:
            print(f"ERROR: {party} already signed this transaction")
            return False
        
        # Проверяем все предыдущие подписи
        if not self.verify_chain(tx_id):
            print(f"ERROR: Previous signatures are invalid!")
            return False
        
        # Вычисляем хэш текущего состояния цепи
        # (оригинальные данные + все предыдущие подписи)
        prev_state = {
            'data': chain.original_data,
            'signatures': [asdict(s) for s in chain.signatures]
        }
        prev_hash = hashlib.sha256(
            json.dumps(prev_state, sort_keys=True).encode()
        ).hexdigest()
        
        # Подписываем prev_hash (это как в blockchain — каждый блок ссылается на предыдущий)
        signature_value = self._sign_with_hmac(prev_hash, party)
        
        # Создаём новую подпись
        sig = Signature(
            party=party,
            timestamp=datetime.now(timezone.utc).isoformat(),
            signature=signature_value,
            prev_hash=prev_hash
        )
        
        # Добавляем в цепочку
        chain.signatures.append(sig)
        
        return True
    
    def verify_chain(self, tx_id: str) -> bool:
        """
        Проверяем всю цепочку подписей
        Каждая подпись должна быть валидной и ссылаться на правильный prev_hash
        
        Returns:
            True если вся цепочка валидна
        """
        chain = self.chains.get(tx_id)
        if not chain:
            return False
        
        # Проверяем каждую подпись
        for i, sig in enumerate(chain.signatures):
            if i == 0:
                # Первая подпись (Alice) — проверяем против оригинальных данных
                data_hash = self._compute_data_hash(chain.original_data)
                if not self._verify_signature(data_hash, sig.signature, sig.party):
                    print(f"FAIL: First signature by {sig.party} is invalid")
                    return False
            else:
                # Последующие подписи — проверяем против prev_hash
                # Пересчитываем prev_hash
                prev_state = {
                    'data': chain.original_data,
                    'signatures': [asdict(s) for s in chain.signatures[:i]]
                }
                expected_prev_hash = hashlib.sha256(
                    json.dumps(prev_state, sort_keys=True).encode()
                ).hexdigest()
                
                # Проверяем что prev_hash правильный
                if sig.prev_hash != expected_prev_hash:
                    print(f"FAIL: {sig.party} prev_hash mismatch")
                    return False
                
                # Проверяем саму подпись
                if not self._verify_signature(sig.prev_hash, sig.signature, sig.party):
                    print(f"FAIL: Signature by {sig.party} is invalid")
                    return False
        
        return True
    
    def get_chain_status(self, tx_id: str) -> dict:
        """
        Получить статус цепочки для UI
        """
        chain = self.chains.get(tx_id)
        if not chain:
            return {'error': 'Chain not found'}
        
        is_valid = self.verify_chain(tx_id)
        
        return {
            'tx_id': tx_id,
            'valid': is_valid,
            'signatures_count': len(chain.signatures),
            'parties': [s.party for s in chain.signatures],
            'chain': chain.to_dict()
        }
    
    def simulate_attack(self, tx_id: str, attack_type: str) -> dict:
        """
        Симулируем атаку на цепочку
        
        attack_type:
        - 'modify_data': изменяем оригинальные данные
        - 'forge_signature': подделываем одну из подписей
        - 'remove_signature': удаляем подпись из середины
        """
        chain = self.chains.get(tx_id)
        if not chain:
            return {'error': 'Chain not found'}
        
        original_valid = self.verify_chain(tx_id)
        
        if attack_type == 'modify_data':
            # Меняем amount в оригинальных данных
            old_amount = chain.original_data.get('amount_eur', 0)
            chain.original_data['amount_eur'] = 99999.99
            
        elif attack_type == 'forge_signature':
            # Подделываем подпись Bob (индекс 1)
            if len(chain.signatures) > 1:
                chain.signatures[1].signature = 'forged_signature_12345'
        
        elif attack_type == 'remove_signature':
            # Удаляем подпись из середины
            if len(chain.signatures) > 2:
                chain.signatures.pop(1)
        
        # Проверяем после атаки
        after_valid = self.verify_chain(tx_id)
        
        return {
            'attack_type': attack_type,
            'before_attack': original_valid,
            'after_attack': after_valid,
            'detected': not after_valid  # если стало invalid — атака обнаружена
        }

# ============================================
# DEMO / TESTS
# ============================================

if __name__ == '__main__':
    print("=" * 70)
    print("Multi-Party Signature Chain Demo")
    print("Scenario: Alice → Bob → Charlie")
    print("=" * 70)
    
    # Создаём протокол
    protocol = MultiPartyProtocol()
    
    # Транзакция
    tx = {
        'tx_id': 'TXN-MULTI-001',
        'sender': 'Alice',
        'recipient': 'Charlie',
        'amount_eur': 1000.00,
        'currency': 'EUR',
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    
    print("\n[1] Alice initiates chain and signs...")
    chain = protocol.initiate_chain(tx, 'Alice')
    print(f"    ✓ Alice signed at {chain.signatures[0].timestamp}")
    
    print("\n[2] Bob adds his signature...")
    success = protocol.add_signature('TXN-MULTI-001', 'Bob')
    if success:
        print(f"    ✓ Bob signed successfully")
    
    print("\n[3] Charlie adds his signature...")
    success = protocol.add_signature('TXN-MULTI-001', 'Charlie')
    if success:
        print(f"    ✓ Charlie signed successfully")
    
    print("\n[4] Verifying full chain...")
    status = protocol.get_chain_status('TXN-MULTI-001')
    print(f"    Chain valid: {status['valid']}")
    print(f"    Parties: {' → '.join(status['parties'])}")
    
    print("\n[5] Simulating MODIFICATION attack...")
    result = protocol.simulate_attack('TXN-MULTI-001', 'modify_data')
    print(f"    Attack detected: {result['detected']}")
    
    print("\n" + "=" * 70)
    print("Demo complete! Multi-party signatures работают корректно.")
    print("=" * 70)
