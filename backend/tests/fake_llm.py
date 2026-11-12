"""Stand-in for the openai SDK so client and pipeline tests never touch the network."""

from types import SimpleNamespace

import httpx2
import openai


def bad_request(message: str = "unsupported response_format") -> openai.BadRequestError:
    response = httpx2.Response(400, request=httpx2.Request("POST", "http://fake/chat/completions"))
    return openai.BadRequestError(message, response=response, body=None)


class FakeSDK:
    """Returns queued replies in order. A queued exception is raised instead; a queued
    callable is called with the request kwargs and its return value is the reply.

    reject_modes lists response_format types the fake provider answers with HTTP 400.
    """

    def __init__(self, replies: list, reject_modes: tuple[str, ...] = ()):
        self.replies = list(replies)
        self.reject_modes = reject_modes
        self.calls: list[dict] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        mode = kwargs.get("response_format", {}).get("type", "instructions")
        if mode in self.reject_modes:
            raise bad_request()
        self.calls.append(kwargs)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        if callable(reply):
            reply = reply(kwargs)
        usage = SimpleNamespace(prompt_tokens=10, completion_tokens=5)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=reply))], usage=usage
        )
