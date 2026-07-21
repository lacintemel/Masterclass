"""Expected SMTP gateway failures."""


class GatewayError(Exception):
    """Base class for a handled gateway failure."""


class MessageParseError(GatewayError):
    """The MIME message could not be parsed safely."""


class MessageLimitError(GatewayError):
    """A configured message or attachment limit was exceeded."""


class AnalyzerScanError(GatewayError):
    """The analyzer failed or returned an unusable result."""


class RelayError(GatewayError):
    """The downstream SMTP relay could not accept the message."""
