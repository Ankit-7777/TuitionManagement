from rest_framework.permissions import BasePermission




class IsSuperAdmin(BasePermission):
    """
    Custom permission to grant full access to superadmin users.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_superuser


class IsTutor(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'tutor'

class IsStudent(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'student'
