from typing import TypeVar, Iterable, Optional

T = TypeVar("T")


def filter_none(i: Iterable[Optional[T]]) -> Iterable[T]:
    return filter(lambda x: x is not None, i)
