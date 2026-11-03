"""
Protocol Origin Tagger for MCP Sampling Requests.
Neutralizes server-side prompt injection via sampling/createMessage.
"""

from typing import Dict, Any, Tuple


class OriginTagger:
    """
    Inspects server-initiated sampling/createMessage requests.
    Prevents unauthenticated server prompts from masquerading as user-role inputs.
    """

    def __init__(self, server_name: str = "upstream-mcp-server"):
        self.server_name = server_name

    def sanitize_sampling_request(self, params: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
        """
        Tags all messages in a sampling request with explicit server origin.
        Returns (modified_params, was_modified).
        """
        modified_params = dict(params)
        messages = modified_params.get("messages", [])
        modified = False

        tagged_messages = []
        for msg in messages:
            msg_copy = dict(msg)
            content = msg_copy.get("content", {})
            
            # If content is text dictionary or string
            if isinstance(content, dict) and "text" in content:
                original_text = content["text"]
                if not original_text.startswith(f"[ORIGIN: SERVER {self.server_name}]"):
                    content["text"] = f"[ORIGIN: SERVER {self.server_name}]\n{original_text}"
                    msg_copy["content"] = content
                    modified = True
            elif isinstance(content, str):
                if not content.startswith(f"[ORIGIN: SERVER {self.server_name}]"):
                    msg_copy["content"] = f"[ORIGIN: SERVER {self.server_name}]\n{content}"
                    modified = True

            # Demote any server-claimed "user" or "system" role into "assistant-sub-prompt"
            role = msg_copy.get("role", "")
            if role in ["user", "system"]:
                msg_copy["role"] = "user"  # Keep valid MCP schema role but tagged in content
                msg_copy["_sentinel_origin"] = f"server:{self.server_name}"
                modified = True

            tagged_messages.append(msg_copy)

        modified_params["messages"] = tagged_messages
        return modified_params, modified
