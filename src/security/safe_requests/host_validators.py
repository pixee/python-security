from abc import ABC, abstractmethod


class BaseHostValidator(ABC):
    def __init__(self, host):
        self.host = host

    @property
    @abstractmethod
    def is_allowed(self):
        pass


class DefaultHostValidator(BaseHostValidator):
    KNOWN_INFRASTRUCTURE_HOSTS = frozenset(
        ("192.168.1.1", "3232235777", "169.254.169.254", "2852039166")
    )

    @property
    def is_allowed(self):
        return self.host not in self.KNOWN_INFRASTRUCTURE_HOSTS
