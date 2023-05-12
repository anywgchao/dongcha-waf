from django.contrib import admin
from django.urls import path
from django.conf.urls import include
from django.conf import settings
from django.conf.urls.static import static
from . import views

urlpatterns = [
                  path('semf/', admin.site.urls),
                  path('', include('RBAC.urls')),
                  path('rule/', include('RuleManage.urls')),
                  path('notice/', include('NoticeManage.urls')),
                  path('waf/', include('WafChartManage.urls')),
                  path('setting/', include('SettingManage.urls')),
              ] + static(settings.STATIC_URL,document_root=settings.STATIC_ROOT)
handler404 = views.page_not_found
handler500 = views.page_error
handler403 = views.permission_denied
