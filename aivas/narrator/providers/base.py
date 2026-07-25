from abc import ABC, abstractmethod


class BaseProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def generate(self, prompt: str, max_tokens: int = 300) -> str: ...

    async def stream(self, messages: list[dict], max_tokens: int = 1024):
        """Yield string tokens. Subclasses must implement as async generator."""
        raise NotImplementedError(f"{self.__class__.__name__}.stream() not implemented")
        yield  # pragma: no cover — makes this an async generator
