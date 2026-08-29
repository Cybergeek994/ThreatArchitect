"""Pydantic schema introspection shared across validation and orchestration."""

from __future__ import annotations

from enum import StrEnum
from typing import get_args, get_origin

from pydantic import BaseModel, ConfigDict, Field
from pydantic.fields import FieldInfo


class ReferenceSuffix(StrEnum):
    """Suffixes that mark foreign-key-style reference fields."""

    ID = "_id"
    IDS = "_ids"


class ReferenceFieldDescriptor(BaseModel):
    """A schema field that carries a foreign-key-style reference."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    field_name: str = Field(strict=True, min_length=1)
    parent_model: str = Field(strict=True, min_length=1)
    is_list: bool


def discover_reference_fields(model: type[BaseModel]) -> tuple[ReferenceFieldDescriptor, ...]:
    """Return all ``*_id`` / ``*_ids`` fields across the model tree."""
    found: list[ReferenceFieldDescriptor] = []
    seen_fields: set[tuple[str, str]] = set()
    visited_models: set[type[BaseModel]] = set()
    _walk_reference_fields(model, found, seen_fields, visited_models)
    return tuple(found)


def reference_fields_for_models(*models: type[BaseModel]) -> frozenset[str]:
    """Collect unique reference field names from one or more Pydantic models."""
    return frozenset(
        descriptor.field_name for model in models for descriptor in discover_reference_fields(model)
    )


def _walk_reference_fields(
    model: type[BaseModel],
    found: list[ReferenceFieldDescriptor],
    seen_fields: set[tuple[str, str]],
    visited_models: set[type[BaseModel]],
) -> None:
    if model in visited_models:
        return
    visited_models.add(model)
    for name, field_info in model.model_fields.items():
        annotation = field_info.annotation
        origin = get_origin(annotation)
        args = get_args(annotation)
        if _is_reference_field_name(name):
            key = (model.__name__, name)
            if key not in seen_fields:
                seen_fields.add(key)
                found.append(
                    ReferenceFieldDescriptor(
                        field_name=name,
                        parent_model=model.__name__,
                        is_list=origin is list or name.endswith(ReferenceSuffix.IDS),
                    )
                )
        nested_models = _nested_model_types(annotation, origin, args)
        for nested in nested_models:
            _walk_reference_fields(nested, found, seen_fields, visited_models)


def _is_reference_field_name(name: str) -> bool:
    if name == "id":
        return False
    return name.endswith(ReferenceSuffix.ID) or name.endswith(ReferenceSuffix.IDS)


def _nested_model_types(
    annotation: object,
    origin: object,
    args: tuple[object, ...],
) -> list[type[BaseModel]]:
    candidates: list[object] = []
    if origin is list and args:
        candidates.append(args[0])
    elif origin is None and isinstance(annotation, type) and issubclass(annotation, BaseModel):
        candidates.append(annotation)
    else:
        for arg in args:
            candidates.append(arg)
    nested: list[type[BaseModel]] = []
    for candidate in candidates:
        inner_origin = get_origin(candidate)
        if inner_origin is not None:
            for inner in get_args(candidate):
                if isinstance(inner, type) and issubclass(inner, BaseModel):
                    nested.append(inner)
            continue
        if isinstance(candidate, type) and issubclass(candidate, BaseModel):
            nested.append(candidate)
    return nested
