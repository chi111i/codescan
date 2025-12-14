"""
优化的调用链分析算法

包含:
- 双向 BFS 路径查找
- 路径缓存
- 智能剪枝策略
- 拓扑排序支持
"""

import logging
from collections import defaultdict, deque
from typing import List, Dict, Set, Tuple, Optional

logger = logging.getLogger(__name__)


class OptimizedPathFinder:
    """优化的路径查找器"""

    def __init__(self, call_graph):
        self.call_graph = call_graph
        # 路径缓存
        self._path_cache: Dict[Tuple[str, frozenset], List[List[str]]] = {}
        # 可达性缓存
        self._reachability: Dict[Tuple[str, str, int], bool] = {}

    def find_paths_bidirectional_bfs(
        self,
        start_id: str,
        target_ids: Set[str],
        max_depth: int = 10,
        max_paths: int = 100,
    ) -> List[List[str]]:
        """双向 BFS 查找路径

        从起点正向搜索，从目标反向搜索，在中间相遇。
        时间复杂度从 O(b^d) 降低到 O(b^(d/2))

        Args:
            start_id: 起始节点
            target_ids: 目标节点集合
            max_depth: 最大深度
            max_paths: 最大路径数

        Returns:
            路径列表
        """
        # 检查缓存
        cache_key = (start_id, frozenset(target_ids))
        if cache_key in self._path_cache:
            logger.debug(f"Hit path cache for {start_id}")
            cached_paths = self._path_cache[cache_key]
            return cached_paths[:max_paths]

        paths_found = []

        # 正向层级：depth -> {node_id: [paths_to_node]}
        forward_layers: Dict[int, Dict[str, List[List[str]]]] = {
            0: {start_id: [[start_id]]}
        }
        # 反向层级
        backward_layers: Dict[int, Dict[str, List[List[str]]]] = {
            0: {tid: [[tid]] for tid in target_ids}
        }

        # 当前层的边界节点
        forward_frontier = {start_id}
        backward_frontier = target_ids.copy()

        for depth in range((max_depth + 1) // 2):
            # 在扩展前检查相遇
            meeting_points = forward_frontier & backward_frontier
            if meeting_points:
                # 找到相遇点，合并路径
                for meeting_node in meeting_points:
                    forward_paths = forward_layers[depth].get(meeting_node, [])
                    backward_paths = backward_layers[depth].get(meeting_node, [])

                    for f_path in forward_paths:
                        for b_path in backward_paths:
                            # 合并路径（去掉重复的中间节点）
                            full_path = f_path + list(reversed(b_path[1:]))
                            if full_path not in paths_found:
                                paths_found.append(full_path)
                                if len(paths_found) >= max_paths:
                                    # 缓存结果
                                    self._path_cache[cache_key] = paths_found
                                    return paths_found

            # 正向扩展
            new_forward_frontier = set()
            forward_layers[depth + 1] = {}

            for node_id in forward_frontier:
                if node_id not in forward_layers[depth]:
                    continue

                for path in forward_layers[depth][node_id]:
                    # 剪枝
                    if self._should_prune_path(path):
                        continue

                    # 扩展
                    for callee_id in self.call_graph._callees.get(node_id, set()):
                        if callee_id not in path:  # 避免环
                            new_path = path + [callee_id]
                            if callee_id not in forward_layers[depth + 1]:
                                forward_layers[depth + 1][callee_id] = []
                            forward_layers[depth + 1][callee_id].append(new_path)
                            new_forward_frontier.add(callee_id)

            # 反向扩展
            new_backward_frontier = set()
            backward_layers[depth + 1] = {}

            for node_id in backward_frontier:
                if node_id not in backward_layers[depth]:
                    continue

                for path in backward_layers[depth][node_id]:
                    # 剪枝（反向路径）
                    if self._should_prune_path(list(reversed(path))):
                        continue

                    # 扩展（反向）
                    for caller_id in self.call_graph._callers.get(node_id, set()):
                        if caller_id not in path:  # 避免环
                            new_path = path + [caller_id]
                            if caller_id not in backward_layers[depth + 1]:
                                backward_layers[depth + 1][caller_id] = []
                            backward_layers[depth + 1][caller_id].append(new_path)
                            new_backward_frontier.add(caller_id)

            forward_frontier = new_forward_frontier
            backward_frontier = new_backward_frontier

            # 如果没有新的边界节点，停止
            if not forward_frontier and not backward_frontier:
                logger.debug(f"Search exhausted at depth {depth}")
                break

        # 缓存结果
        if len(paths_found) > 0:
            self._path_cache[cache_key] = paths_found

        logger.debug(f"Found {len(paths_found)} paths from {start_id} using bidirectional BFS")
        return paths_found[:max_paths]

    def _should_prune_path(self, current_path: List[str]) -> bool:
        """判断路径是否应该被剪枝"""
        if len(current_path) == 0:
            return False

        # 1. 路径过长
        if len(current_path) > 15:
            return True

        # 2. 检查最后一个节点
        last_node = self.call_graph.get_node(current_path[-1])
        if not last_node:
            return False

        # 低价值节点（工具函数）
        low_value_patterns = [
            'log', 'logger', 'print', 'debug', 'trace',
            'assert', 'validate', 'check', 'test',
            '__str__', '__repr__', 'to_string', 'toString',
            'get', 'set',  # 简单的 getter/setter
        ]
        last_name_lower = last_node.name.lower()
        if any(pattern in last_name_lower for pattern in low_value_patterns):
            return True

        # 3. 检查是否是外部库函数（低价值）
        if last_node.metadata.get("is_external") and len(current_path) > 3:
            # 外部函数在深层路径中优先级低
            return True

        return False

    def compute_topological_order(self) -> List[str]:
        """计算调用图的拓扑排序（Kahn 算法）

        用于优化污点分析的遍历顺序

        Returns:
            拓扑排序的节点 ID 列表
        """
        # 计算入度
        in_degree = {nid: 0 for nid in self.call_graph.nodes}
        for edge in self.call_graph.edges:
            in_degree[edge.callee_id] += 1

        # 从入度为 0 的节点开始（入口点或独立函数）
        queue = deque([nid for nid, deg in in_degree.items() if deg == 0])
        topo_order = []

        while queue:
            node_id = queue.popleft()
            topo_order.append(node_id)

            # 减少后继的入度
            for callee_id in self.call_graph._callees.get(node_id, set()):
                in_degree[callee_id] -= 1
                if in_degree[callee_id] == 0:
                    queue.append(callee_id)

        # 处理环（强连通分量）
        if len(topo_order) < len(self.call_graph.nodes):
            remaining = set(self.call_graph.nodes) - set(topo_order)
            logger.warning(f"Detected {len(remaining)} nodes in cycles")
            topo_order.extend(remaining)

        return topo_order

    def clear_cache(self):
        """清空缓存"""
        self._path_cache.clear()
        self._reachability.clear()
        logger.debug("Path cache cleared")
