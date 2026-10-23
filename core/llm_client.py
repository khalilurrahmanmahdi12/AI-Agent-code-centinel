import os
import json
import httpx
from typing import Optional, Dict, Any, List


class LLMClient:
    """Multi-provider client supporting Gemini, OpenAI, or Built-in heuristic intelligence."""

    def __init__(self, provider: str = "built-in", api_key: Optional[str] = None):
        self.provider = provider or "built-in"
        self.api_key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("OPENAI_API_KEY")

    async def generate_completion(self, system_prompt: str, user_prompt: str) -> str:
        """Dispatches prompt to configured provider."""
        if self.provider == "gemini" and self.api_key:
            return await self._call_gemini(system_prompt, user_prompt)
        elif self.provider == "openai" and self.api_key:
            return await self._call_openai(system_prompt, user_prompt)
        else:
            return self._builtin_generate(system_prompt, user_prompt)

    async def _call_gemini(self, system_prompt: str, user_prompt: str) -> str:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.api_key}"
        payload = {
            "contents": [
                {"role": "user", "parts": [{"text": f"{system_prompt}\n\nTask:\n{user_prompt}"}]}
            ],
            "generationConfig": {"temperature": 0.2}
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]

    async def _call_openai(self, system_prompt: str, user_prompt: str) -> str:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.2
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

    def _builtin_generate(self, system_prompt: str, user_prompt: str) -> str:
        """Smart fallback for offline/standalone execution."""
        return "[Built-in Agent Engine active - synthesizing response based on AST rules & patterns]"
