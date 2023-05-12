#coding:utf-8


from django.urls import path
from . import views


urlpatterns = [
    path('official/', views.OfficialView, name='officialView'),
    path('custom/', views.CustomView, name='customView'),

    path('custom/create', views.rules_create, name='rulescreate'),
    path('custom/rulegrop_update/<str:rules_id>/', views.rulegrop_update, name='rulesupdate'),

    path('custom/rule_update/<str:rule_id>/', views.rule_update, name='ruleupdate'),
    path('custom/tails/create/<str:rules_id>/', views.ruledetailcreate, name='ruledetailscreate'),

    path('custom/ruleslist', views.rulestablelist, name='rulestablelist'),
    path('custom/details/<str:rules_id>/', views.rulesdetailsview, name='rulesdetailsview'),
    path('custom/detail/<str:rules_id>/', views.rulesdetaillist, name='rulesdetaillist'),

    path('custom/ruledel/<str:rule_id>/', views.rule_del, name='ruledel'),

    path('official/ccgroupcreate', views.ccgroup_create, name='ccgroupcreate'),
    path('official/cc/create/<str:ccgroup_id>/', views.ccdetail_create, name='ccdetailscreate'),

    path('official/cc_update/<str:cc_id>/', views.cc_update, name='ccupdate'),
    path('official/ccgrop_update/<str:ccgroup_id>/', views.ccgroup_update, name='ccgroupupdate'),

    path('official/ccgrouplist', views.ccgrouptablelist, name='ccgrouplist'),
    path('official/detail/<str:ccgroup_id>/', views.ccdetaillist, name='ccdetaillist'),

    path('official/details/<str:ccgroup_id>/', views.ccdetailsview, name='ccdetailsview'),
    path('official/delcc/<str:cc_id>/', views.cc_del, name='delcc'),

]