"""Read-only MCP server for CyberRecon evidence and local threat intelligence."""


def create_server():
    """Create the MCP server lazily to keep data modules importable standalone."""
    from cyberrecon.mcp_server.server import create_server as _create_server

    return _create_server()

__all__ = ["create_server"]
