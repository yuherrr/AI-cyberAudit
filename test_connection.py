import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(
    api_key=os.getenv("LITELLM_MASTER_KEY"), 
    base_url="http://localhost:4000"
)

# Send a test request
response = client.chat.completions.create(
    model="agent-gpt", # This is the model alias you defined in your config
    messages=[{"role": "user", "content": "Hello! Are you working?"}]
)

print(response.choices[0].message.content)
