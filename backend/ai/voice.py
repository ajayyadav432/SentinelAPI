import os
import io
import tempfile
import logging
from typing import Optional, Dict, Any
import httpx

logger = logging.getLogger("sentinel.voice")

class VoiceProcessor:
    """Processes speech audio into text using Python SpeechRecognition and Gemini 2.0 Flash."""

    def __init__(self, gemini_api_key: Optional[str] = None):
        self.gemini_api_key = gemini_api_key or os.environ.get("GEMINI_API_KEY", "")

    async def transcribe_audio(self, audio_bytes: bytes, content_type: str = "audio/webm", language: str = "en") -> Dict[str, Any]:
        """Transcribes incoming audio bytes to text with dual engine support."""
        if not audio_bytes or len(audio_bytes) < 100:
            return {"text": "", "error": "Empty or corrupted audio recording."}

        # Method 1: Try Gemini 2.0 Flash Multimodal Audio Transcription if API Key is set
        if self.gemini_api_key and len(self.gemini_api_key) > 10:
            try:
                gemini_text = await self._transcribe_with_gemini(audio_bytes, content_type, language)
                if gemini_text and len(gemini_text.strip()) > 0:
                    return {
                        "text": gemini_text.strip(),
                        "engine": "gemini_2_0_flash",
                        "status": "success"
                    }
            except Exception as e:
                logger.warning(f"Gemini voice transcription failed, falling back to SpeechRecognition: {e}")

        # Method 2: Standard Python SpeechRecognition Engine
        try:
            import speech_recognition as sr
            from pydub import AudioSegment

            # Write raw audio to temporary file
            with tempfile.NamedTemporaryFile(suffix=".webm", delete=False) as raw_file:
                raw_file.write(audio_bytes)
                raw_path = raw_file.name

            # Convert to standard WAV format for SpeechRecognition
            wav_path = raw_path + ".wav"
            try:
                # Load with pydub
                audio_seg = AudioSegment.from_file(raw_path)
                audio_seg.export(wav_path, format="wav")
            except Exception as conv_err:
                # If pydub fails on webm, try raw write if already wav
                logger.info(f"Pydub format conversion attempt: {conv_err}")
                wav_path = raw_path

            recognizer = sr.Recognizer()
            with sr.AudioFile(wav_path) as source:
                audio_data = recognizer.record(source)

            # Transcribe via Google Speech Recognition
            lang_code = "hi-IN" if language == "hi" else "en-US"
            transcript = recognizer.recognize_google(audio_data, language=lang_code)

            # Cleanup
            for p in [raw_path, wav_path]:
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except Exception:
                        pass

            return {
                "text": transcript,
                "engine": "python_speech_recognition",
                "status": "success"
            }

        except Exception as e:
            logger.error(f"Speech recognition error: {e}")
            err_msg = str(e)
            if "UnknownValueError" in str(type(e)):
                err_msg = "Could not understand audio. Please speak clearly into your microphone."
            elif "RequestError" in str(type(e)):
                err_msg = "Speech recognition network request failed. Check internet connectivity."

            return {
                "text": "",
                "error": err_msg,
                "status": "failed"
            }

    async def _transcribe_with_gemini(self, audio_bytes: bytes, mime_type: str, language: str) -> Optional[str]:
        import base64
        b64_audio = base64.b64encode(audio_bytes).decode("utf-8")
        clean_mime = "audio/webm" if "webm" in mime_type else "audio/wav" if "wav" in mime_type else "audio/mp3"

        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key={self.gemini_api_key}"
        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "inlineData": {
                                "mimeType": clean_mime,
                                "data": b64_audio
                            }
                        },
                        {
                            "text": f"Transcribe the spoken words in this audio exactly in {'Hindi' if language == 'hi' else 'English'}. Return ONLY the transcribed text without quotes or commentary."
                        }
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.0
            }
        }

        async with httpx.AsyncClient(timeout=20.0) as client:
            res = await client.post(url, json=payload)
            if res.status_code == 200:
                data = res.json()
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        return parts[0].get("text", "")
        return None
