from django.contrib import admin
from . import models


# Register your models here.
admin.site.register(models.Setting_template)
admin.site.register(models.Setting_deploy)
admin.site.register(models.Setting_uuid)
admin.site.register(models.Setting_time)



