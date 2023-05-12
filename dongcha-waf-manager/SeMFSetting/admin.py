# coding:utf-8
from django.contrib import admin
from . import models


# Register your models here.

class PocagentAdmin(admin.ModelAdmin):
    list_display = ('agent_name', 'agent_url', 'agent_version', 'agent_label', 'starttime', 'color_code')
    search_fields = ('agent_name',)

    def get_search_results(self, request, queryset, search_term):
        queryset, use_distinct = super(PocagentAdmin, self).get_search_results(request, queryset, search_term)
        try:
            search_term_as_int = int(search_term)
            queryset |= self.model.objects.filter(age=search_term_as_int)
        except:
            pass
        return queryset, use_distinct


class PortagentAdmin(admin.ModelAdmin):
    list_display = ('agent_name', 'agent_url', 'agent_version', 'agent_label', 'starttime', 'color_code')
    search_fields = ('agent_name',)

    def get_search_results(self, request, queryset, search_term):
        queryset, use_distinct = super(PortagentAdmin, self).get_search_results(request, queryset, search_term)
        try:
            search_term_as_int = int(search_term)
            queryset |= self.model.objects.filter(age=search_term_as_int)
        except:
            pass
        return queryset, use_distinct


class LogagentAdmin(admin.ModelAdmin):
    list_display = ('agent_name', 'agent_url', 'agent_version', 'agent_label', 'starttime', 'color_code')
    search_fields = ('agent_name',)

    def get_search_results(self, request, queryset, search_term):
        queryset, use_distinct = super(LogagentAdmin, self).get_search_results(request, queryset, search_term)
        try:
            search_term_as_int = int(search_term)
            queryset |= self.model.objects.filter(age=search_term_as_int)
        except:
            pass
        return queryset, use_distinct


admin.site.site_header = '土夫WEB安全防御平台后台'
admin.site.site_title = '土夫WEB安全防御平台后台'
