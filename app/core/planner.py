from __future__ import annotations

import heapq
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

Point = Tuple[int, int]


class GridPlanner:
    def __init__(self, width: int, height: int, obstacles: Sequence[Point]):
        self.width = width
        self.height = height
        self.obstacles: Set[Point] = set(obstacles)

    def in_bounds(self, p: Point) -> bool:
        x, y = p
        return 0 <= x < self.width and 0 <= y < self.height

    def passable(self, p: Point) -> bool:
        return p not in self.obstacles

    def neighbors(self, p: Point) -> Iterable[Point]:
        x, y = p
        cand = [(x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1)]
        for n in cand:
            if self.in_bounds(n) and self.passable(n):
                yield n

    @staticmethod
    def heuristic(a: Point, b: Point) -> int:
        return abs(a[0] - b[0]) + abs(a[1] - b[1])

    def find_path(self, start: Point, goal: Point) -> List[Point]:
        if not self.in_bounds(start) or not self.in_bounds(goal):
            return []
        if not self.passable(goal):
            return []

        frontier: List[Tuple[int, Point]] = []
        heapq.heappush(frontier, (0, start))
        came_from: Dict[Point, Optional[Point]] = {start: None}
        cost_so_far: Dict[Point, int] = {start: 0}

        while frontier:
            _, current = heapq.heappop(frontier)

            if current == goal:
                break

            for nxt in self.neighbors(current):
                new_cost = cost_so_far[current] + 1
                if nxt not in cost_so_far or new_cost < cost_so_far[nxt]:
                    cost_so_far[nxt] = new_cost
                    priority = new_cost + self.heuristic(nxt, goal)
                    heapq.heappush(frontier, (priority, nxt))
                    came_from[nxt] = current

        if goal not in came_from:
            return []

        path: List[Point] = []
        cur: Optional[Point] = goal
        while cur and cur != start:
            path.append(cur)
            cur = came_from[cur]
        path.reverse()
        return path
