from django.contrib import admin
from . import models

# Register your models here.
admin.site.register(models.Rules_group)
admin.site.register(models.Rules)
admin.site.register(models.CC_group)
admin.site.register(models.CC_rule)
