"""In-process knowledge graph connecting discovered assets.

Deliberately dependency-free (adjacency dicts). A networkx- or Neo4j-backed
implementation can replace it behind the `KnowledgeGraph` Protocol. Assets are
deduplicated by their stable ``key`` (``type:value``); the highest-confidence
copy wins and attributes are merged.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from recon_platform.domain.enums import AssetType
from recon_platform.domain.schemas import Asset, Relation


class InMemoryKnowledgeGraph:
    """Adjacency-list graph of assets and typed relations."""

    def __init__(self) -> None:
        self._assets: dict[str, Asset] = {}
        self._relations: list[Relation] = []
        self._adjacency: dict[str, set[str]] = defaultdict(set)

    def add_asset(self, asset: Asset) -> None:
        existing = self._assets.get(asset.key)
        if existing is None:
            self._assets[asset.key] = asset
            return
        # Merge: keep higher confidence, union attributes.
        merged_attrs = {**existing.attributes, **asset.attributes}
        if asset.confidence > existing.confidence:
            asset.attributes = merged_attrs
            self._assets[asset.key] = asset
        else:
            existing.attributes = merged_attrs

    def add_relation(self, relation: Relation) -> None:
        self._relations.append(relation)
        self._adjacency[relation.source_key].add(relation.target_key)
        self._adjacency[relation.target_key].add(relation.source_key)

    def assets(self, type_: AssetType | None = None) -> list[Asset]:
        values = list(self._assets.values())
        if type_ is None:
            return values
        return [a for a in values if a.type == type_]

    def relations(self) -> list[Relation]:
        return list(self._relations)

    def neighbors(self, asset_key: str) -> list[Asset]:
        return [self._assets[k] for k in self._adjacency.get(asset_key, set()) if k in self._assets]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a nodes/edges structure suitable for graph viz."""
        return {
            "nodes": [
                {
                    "id": a.key,
                    "type": a.type.value,
                    "value": a.value,
                    "confidence": a.confidence,
                    "attributes": a.attributes,
                }
                for a in self._assets.values()
            ],
            "edges": [
                {"source": r.source_key, "target": r.target_key, "type": r.type.value}
                for r in self._relations
            ],
        }
