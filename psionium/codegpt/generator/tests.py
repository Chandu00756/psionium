from django.test import TestCase, Client
from django.urls import reverse
from .models import GeneratedCode

class GeneratorTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.test_prompt = "Write a Python function to calculate the factorial of a number."
        self.test_code = "def factorial(n):\n    if n == 0:\n        return 1\n    else:\n        return n * factorial(n-1)"

    def test_generate_code(self):
        """Test the code generation endpoint."""
        response = self.client.post(
            reverse('generate_code'),
            data={'prompt': self.test_prompt, 'max_tokens': 500, 'temperature': 0.7},
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('code', response.json())

    def test_execute_code(self):
        """Test the code execution endpoint."""
        response = self.client.post(
            reverse('execute_code'),
            data={'code': self.test_code},
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('output', response.json())