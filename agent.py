from openai import OpenAI

client = OpenAI(
  api_key=os.environ["OPENAI_API_KEY"]
)

response = client.responses.create(
  model="gpt-5-nano",
  input="write a haiku about ai",
  store=True,
)

print(response.output_text);
