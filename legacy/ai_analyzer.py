import os
import re
import asyncio
from dotenv import load_dotenv
from colorama import Fore, Style, init
from urllib.parse import urlparse

try:
    from google import genai
except ImportError:
    genai = None

try:
    from groq import Groq
except ImportError:
    Groq = None

init(autoreset=True)
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
DEFAULT_GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
DEFAULT_GROQ_MODEL = "llama3-8b-8192"

class AIAnalyzer:
    def __init__(self):
        self.gemini_client = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY and genai else None
        self.groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY and Groq else None

    async def analyze_with_gemini(self, prompt: str):
        if not self.gemini_client:
            return None
        try:
            # Using the new google.genai SDK
            response = await asyncio.to_thread(
                self.gemini_client.models.generate_content,
                model=DEFAULT_GEMINI_MODEL,
                contents=prompt
            )
            return response.text
        except Exception as e:
            return f"Gemini Error: {str(e)}"

    async def analyze_with_groq(self, prompt: str):
        if not self.groq_client:
            return None
        try:
            response = await asyncio.to_thread(
                self.groq_client.chat.completions.create,
                messages=[{"role": "user", "content": prompt}],
                model=DEFAULT_GROQ_MODEL,
                temperature=0.2,
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Groq Error: {str(e)}"

    async def get_dual_analysis(self, target: str):
        payload, source_desc = self._normalize_input(target)
        prompt = self._build_prompt(payload, source_desc)
        
        # Dual-LLM concurrent execution
        tasks = []
        if self.gemini_client:
            tasks.append(self.analyze_with_gemini(prompt))
        if self.groq_client:
            tasks.append(self.analyze_with_groq(prompt))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results

    def _normalize_input(self, value):
        value = value.strip().strip('"\'')
        if os.path.exists(value):
            with open(value, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read(), f"file '{value}'"
        if re.match(r'^https?://', value, re.I) or re.match(r'^[\w.-]+\.[a-zA-Z]{2,}(/.*)?$', value):
            if not value.lower().startswith("http"):
                value = f"http://{value}"
            return value, f"URL '{value}'"
        return value, "raw text"

    def _build_prompt(self, payload, source_desc):
        return f"""
        You are an Elite SOC Engineer. Provide a forensic phishing assessment.
        Target: {source_desc}
        
        Format your response EXACTLY as follows:
        VERDICT: [SAFE/SUSPICIOUS/MALICIOUS]
        CONFIDENCE: [0-100]%
        THREAT_LEVEL: [LOW/MEDIUM/HIGH/CRITICAL]
        ANALYSIS: [Brief technical breakdown]
        RED_FLAGS: [Bullet points]
        
        Content:
        {payload}
        """

