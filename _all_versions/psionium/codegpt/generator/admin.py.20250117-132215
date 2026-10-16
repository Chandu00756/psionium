from django.contrib import admin
from .models import GeneratedCode

# Register the GeneratedCode model with the admin site
@admin.register(GeneratedCode)
class GeneratedCodeAdmin(admin.ModelAdmin):
    list_display = ('id', 'prompt', 'code', 'created_at')
    search_fields = ('prompt', 'code')
    list_filter = ('created_at',)