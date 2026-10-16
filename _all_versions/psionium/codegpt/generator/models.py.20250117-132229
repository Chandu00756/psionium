from django.db import models

class GeneratedCode(models.Model):
    """Model to store generated code and its metadata."""
    prompt = models.TextField(help_text="The user's input prompt for code generation.")
    code = models.TextField(help_text="The generated code.")
    created_at = models.DateTimeField(auto_now_add=True, help_text="The timestamp when the code was generated.")

    def __str__(self):
        return f"Generated Code #{self.id}"