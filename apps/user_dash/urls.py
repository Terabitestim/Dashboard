from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index),
    url(r'^registration$', views.registration),
    url(r'^register$', views.register),
    url(r'^login$', views.login),
    url(r'^dashboard$', views.dashboard),
    url(r'^dashboard/admin$', views.dashboard_admin),
    url(r'^users/new$', views.add_new),
    url(r'^users/process$', views.add),
    url(r'^users/show/(?P<user_id>\w+)$', views.show),
    url(r'^users/post/(?P<user_id>\w+)$', views.post),
    url(r'^users/edit/(?P<user_id>\w+)$', views.edit),
    url(r'^users/update/(?P<user_id>\w+)$', views.edit_user),
    url(r'^logout$', views.logout),
    url(r'^users/profile/(?P<user_id>\w+)$', views.profile),
    url(r'^users/profile/update/(?P<user_id>\w+)$', views.edit_profile)
]