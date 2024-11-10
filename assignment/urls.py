from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework.routers import DefaultRouter
from .views import UserAuthAPIView, AssignmentViewSet, AssignmentSubmissionViewSet

router = DefaultRouter()
router.register(r'assignments', AssignmentViewSet)
router.register(r'submissions', AssignmentSubmissionViewSet)


urlpatterns = [
    path('', include(router.urls)),
    path('auth/', UserAuthAPIView.as_view(), name='user-auth'),
]
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

"""
GET Request - View a Specific User's Profile by user_id
URL: /auth/?action=manage_users&user_action=view&user_id=<user_id>

GET Request - List All Users
URL: /auth/?action=manage_users&user_action=list

POST Request - Register a New User
URL: /auth/?action=register

POST Request - Login a User
URL: /auth/?action=login

POST Request - Delete a User (Superuser only)
URL: /auth/?action=manage_users&user_action=delete&user_id=<user_id>

POST Request - Update a User's Profile (Superuser only)
URL: /auth/?action=manage_users&user_action=update&user_id=<user_id>

"""



