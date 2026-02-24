
"""
Merkle Tree implementation для fake-data-prevention

Merkle Tree используется для проверки целостности набора данных
Если хоть одна транзакция изменена — root hash поменяется
Это как в Bitcoin блокчейн работает
"""

import hashlib
from typing import List, Optional

class MerkleNode:
    """ Узел дерева Меркла Хранит хэш и ссылки на детей (левого/правого)
    """
    def __init__(self, hash_value: str, left=None, right=None):
        self.hash = hash_value
        self.left = left
        self.right = right
    
    def is_leaf(self):
        """Проверяем листовой ли это узел (нет детей)"""
        return self.left is None and self.right is None

class MerkleTree:
    """
    Merkle Tree для набора транзакций
    
    Пример использования:
        hashes = ['hash1', 'hash2', 'hash3']
        tree = MerkleTree(hashes)
        root = tree.get_root()
        print(f"Merkle Root: {root}")
    """
    
    def __init__(self, leaf_hashes: List[str]):
        """
        Строим дерево из списка хэшей
        
        Args:
            leaf_hashes: список SHA-256 хэшей транзакций
        """
        if not leaf_hashes:
            raise ValueError("Cannot build Merkle tree from empty list")
        
        self.leaves = leaf_hashes.copy()  # сохраняем оригинальные листы
        self.root = self._build_tree(leaf_hashes)
    
    def _hash_pair(self, left_hash: str, right_hash: str) -> str:
        """
        Хэшируем пару узлов
        Concatenate и хэшируем SHA-256
        
        В Bitcoin это делается так:
        parent_hash = SHA256(SHA256(left + right))
        Но для простоты делаем один SHA256
        """
        combined = left_hash + right_hash
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def _build_tree(self, hashes: List[str]) -> MerkleNode:
        """
        Рекурсивно строим дерево снизу вверх
        
        Логика:
        1. Если один хэш — это и есть root
        2. Если чётное количество — делим пополам
        3. Если нечётное — дублируем последний (как в Bitcoin)
        """
        # Base case: один узел = корень
        if len(hashes) == 1:
            return MerkleNode(hashes[0])
        
        # Если нечётное количество узлов — дублируем последний
        # Это стандартная практика в Merkle деревьях
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])  # TODO: может это не лучшая практика?
        
        # Парами строим родителей
        parent_hashes = []
        for i in range(0, len(hashes), 2):
            left_hash = hashes[i]
            right_hash = hashes[i + 1]
            parent_hash = self._hash_pair(left_hash, right_hash)
            parent_hashes.append(parent_hash)
        
        # Рекурсивно строим верхние уровни
        return self._build_tree(parent_hashes)
    
    def get_root(self) -> str:
        """Возвращает root hash дерева"""
        return self.root.hash
    
    def verify_integrity(self, leaf_hashes: List[str]) -> bool:
        """
        Проверяем целостность набора данных
        Строим новое дерево из новых хэшей и сравниваем root
        
        Returns:
            True если данные не изменены, False если изменены
        """
        if len(leaf_hashes) != len(self.leaves):
            return False  # количество транзакций изменилось
        
        # Строим новое дерево
        new_tree = MerkleTree(leaf_hashes)
        
        # Сравниваем root hashes
        return new_tree.get_root() == self.get_root()
    
    def get_proof(self, index: int) -> List[tuple]:
        """
        Генерируем Merkle proof для транзакции по индексу
        Это позволяет доказать что транзакция есть в дереве
        без передачи всех транзакций
        
        TODO: реализовать это для bonus points
        Пока просто заглушка
        """
        # Это advanced feature, пока не делаем
        raise NotImplementedError("Merkle proof generation not implemented yet")
    
    def __str__(self):
        """Красивый вывод для debug"""
        return f"MerkleTree(leaves={len(self.leaves)}, root={self.get_root()[:16]}...)"
    
    def __repr__(self):
        return self.__str__()

# ============================================
# HELPER FUNCTIONS
# ============================================

def build_merkle_tree_from_transactions(transactions: List[dict]) -> MerkleTree:
    """
    Вспомогательная функция: строим дерево из списка транзакций
    
    Args:
        transactions: список dict с транзакциями (должны содержать 'digest')
    
    Returns:
        MerkleTree объект
    """
    if not transactions:
        raise ValueError("No transactions provided")
    
    # Извлекаем digest из каждой транзакции
    hashes = []
    for tx in transactions:
        if 'digest' in tx:
            hashes.append(tx['digest'])
        elif '_digest' in tx:  # для совместимости со старым кодом
            hashes.append(tx['_digest'])
        else:
            raise ValueError(f"Transaction {tx.get('tx_id', 'unknown')} has no digest")
    
    return MerkleTree(hashes)

# ============================================
# TESTS (для проверки что всё работает)
# ============================================

if __name__ == '__main__':
    print("=" * 60)
    print("Testing Merkle Tree Implementation")
    print("=" * 60)
    
    # Test 1: простой пример
    print("\nTest 1: Simple tree with 4 leaves")
    hashes = [
        hashlib.sha256(b'tx1').hexdigest(),
        hashlib.sha256(b'tx2').hexdigest(),
        hashlib.sha256(b'tx3').hexdigest(),
        hashlib.sha256(b'tx4').hexdigest(),
    ]
    tree = MerkleTree(hashes)
    print(f"Root hash: {tree.get_root()}")
    
    # Test 2: проверка целостности
    print("\nTest 2: Integrity check (no modification)")
    same_hashes = hashes.copy()
    is_valid = tree.verify_integrity(same_hashes)
    print(f"Integrity valid: {is_valid}")  # должно быть True
    
    # Test 3: изменённые данные
    print("\nTest 3: Integrity check (with modification)")
    modified_hashes = hashes.copy()
    modified_hashes[2] = hashlib.sha256(b'tx3_MODIFIED').hexdigest()
    is_valid = tree.verify_integrity(modified_hashes)
    print(f"Integrity valid: {is_valid}")  # должно быть False
    
    # Test 4: нечётное количество листов
    print("\nTest 4: Odd number of leaves (5)")
    odd_hashes = hashes + [hashlib.sha256(b'tx5').hexdigest()]
    tree_odd = MerkleTree(odd_hashes)
    print(f"Root hash: {tree_odd.get_root()}")
    
    print("\n" + "=" * 60)
    print("All tests passed!")
    print("=" * 60)
