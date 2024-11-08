from rest_framework import viewsets
from django.contrib.auth import authenticate, login
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import AllowAny
from .models import Assignment, AssignmentSubmission, User
from .serializers import AssignmentSerializer, AssignmentSubmissionSerializer, UserProfileSerializer, SignupSerializer
from .utils import get_tokens_for_user
from .pagination import MyPageNumberPagination
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import PermissionDenied
from .permissions import IsTutor, IsStudent
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from .permissions import IsSuperAdmin



class UserAuthAPIView(APIView):
    permission_classes = [AllowAny] 
    
    def get(self, request, *args, **kwargs):
        action = request.query_params.get('action')
        user_action = request.query_params.get('user_action')
        user_id = request.query_params.get('user_id')
        
        if action == 'manage_users' and user_action:
            if user_action == 'view' and user_id:
                try:
                    user = User.objects.get(id=user_id)
                    return Response(UserProfileSerializer(user).data, status=status.HTTP_200_OK)
                except User.DoesNotExist:
                    return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            
            elif user_action == 'list':
                users = User.objects.all()
                return Response(UserProfileSerializer(users, many=True).data, status=status.HTTP_200_OK)
        
        return Response({'error': 'Invalid action or parameters'}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, *args, **kwargs):
        action = request.query_params.get('action')
        
        if action == 'register':
            return self.signup(request)
        elif action == 'login':
            return self.login(request)
        elif action == 'manage_users':
            return self.manage_users(request)
        else:
            return Response({'error': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)

    def signup(self, request):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            login(request, user)
            token = get_tokens_for_user(user)
            return Response({
                'message': 'Registration successful',
                'token': token,
                'user_data': UserProfileSerializer(user).data
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def login(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        
        if not email:
            return Response({'error': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not password:
            return Response({'error': 'Password is required.'}, status=status.HTTP_400_BAD_REQUEST)
        
        user = authenticate(request, email=email, password=password)
        if user:
            login(request, user)
            token = get_tokens_for_user(user)
            return Response({
                'message': 'Login successful',
                'token': token,
                'user_data': UserProfileSerializer(user).data
            }, status=status.HTTP_200_OK)
        
        return Response({'error': 'Invalid email or password'}, status=status.HTTP_401_UNAUTHORIZED)

    def manage_users(self, request):
        # Only superadmins can manage users
        if not request.user.is_superuser:
            return Response({'error': 'You do not have permission to manage users.'}, status=status.HTTP_403_FORBIDDEN)
        
        user_action = request.query_params.get('user_action')
        user_id = request.query_params.get('user_id')
        
        if user_action == 'delete' and user_id:
            try:
                user = User.objects.get(id=user_id)
                user.delete()
                return Response({'message': 'User deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        elif user_action == 'update' and user_id:
            try:
                user = User.objects.get(id=user_id)
                serializer = UserProfileSerializer(user, data=request.data, partial=True)
                if serializer.is_valid():
                    serializer.save()
                    return Response({'message': 'User updated successfully.'}, status=status.HTTP_200_OK)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        return Response({'error': 'Invalid action or parameters'}, status=status.HTTP_400_BAD_REQUEST)


# class UserAuthAPIView(APIView):
#     permission_classes = [AllowAny]

#     def post(self, request, *args, **kwargs):
#         action = request.query_params.get('action')
#         if action == 'register':
#             return self.signup(request)
#         elif action == 'login':
#             return self.login(request)
#         else:
#             return Response({'error': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)

#     def signup(self, request):
#         serializer = SignupSerializer(data=request.data)
#         if serializer.is_valid():
#             user = serializer.save()
#             login(request, user)
#             token = get_tokens_for_user(user)
            
#             return Response({
#                 'message': 'Registration successful',
#                 'token': token,
#                 'user_data': UserProfileSerializer(user).data
#             }, status=status.HTTP_201_CREATED)

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def login(self, request):
#         email = request.data.get('email')
#         password = request.data.get('password')

#         if not email:
#             return Response({'error': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)

#         if not password:
#             return Response({'error': 'Password is required.'}, status=status.HTTP_400_BAD_REQUEST)

#         user = authenticate(request, email=email, password=password)
#         if user:
#             login(request, user)
#             token = get_tokens_for_user(user)

#             return Response({
#                 'message': 'Login successful',
#                 'token': token,
#                 'user_data': UserProfileSerializer(user).data
#             }, status=status.HTTP_200_OK)
        
#         return Response({'error': 'Invalid email or password'}, status=status.HTTP_401_UNAUTHORIZED)

class AssignmentViewSet(viewsets.ModelViewSet):
    queryset = Assignment.objects.all()
    serializer_class = AssignmentSerializer
    authentication_classes = [JWTAuthentication]
    pagination_class = MyPageNumberPagination

    def get_permissions(self):
        """
        Apply different permissions based on the action.
        Tutors can create, update, and delete assignments.
        Students can view assignments.
        """
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            permission_classes = [IsAuthenticated, IsTutor]
        else:
            permission_classes = [IsAuthenticated, (IsStudent | IsTutor)]
        self.permission_classes = permission_classes
        return super().get_permissions()

    def list(self, request, *args, **kwargs):
        """
        List all assignments with pagination.
        """
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

 
    def create(self, request, *args, **kwargs):
        """
        Create a new assignment. Only available to tutors.
        Automatically sets the tutor field to the logged-in user.
        """
        # Set the tutor to the logged-in user
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(tutor=request.user)  # Automatically set tutor
        
        headers = self.get_success_headers(serializer.data)
        return Response({
            "message": "Assignment created successfully.",
            "data": serializer.data
        }, status=status.HTTP_201_CREATED, headers=headers)

    
    def retrieve(self, request, *args, **kwargs):
        """
        Retrieve a single assignment.
        """
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response({
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        """
        Fully update an assignment. Only available to tutors.
        """
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            "message": "Assignment updated successfully.",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def partial_update(self, request, *args, **kwargs):
        """
        Partially update an assignment. Only available to tutors.
        """
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            "message": "Assignment partially updated successfully.",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        """
        Delete an assignment. Only available to tutors.
        """
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({
            "message": "Assignment deleted successfully."
        }, status=status.HTTP_204_NO_CONTENT)

class AssignmentSubmissionViewSet(viewsets.ModelViewSet):
    queryset = AssignmentSubmission.objects.all()
    serializer_class = AssignmentSubmissionSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsStudent]

    def get_permissions(self):
        """
        Apply different permissions based on the action.
        Students can create, view, update their own submissions.
        """
        if self.action in ['create', 'update', 'partial_update']:
            permission_classes = [IsAuthenticated, IsStudent]
        elif self.action == 'destroy':
            permission_classes = [IsAuthenticated, IsStudent]
        else:
            permission_classes = [IsAuthenticated, IsStudent]
        self.permission_classes = permission_classes
        return super().get_permissions()

    def list(self, request, *args, **kwargs):
        """
        List submissions. A student can only view their own submissions.
        """
        queryset = self.filter_queryset(self.get_queryset())
        queryset = queryset.filter(student=request.user)
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        """
        Create a new submission for the student.
        Only students can submit assignments.
        """
        data = request.data.copy()
        data['student'] = request.user.id
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response({
            "message": "Assignment submission created successfully.",
            "data": serializer.data
        }, status=status.HTTP_201_CREATED, headers=headers)

    def retrieve(self, request, *args, **kwargs):
        """
        Retrieve a specific submission by its ID.
        Students can view their own submissions.
        """
        instance = self.get_object()

        if instance.student != request.user:
            return Response({
                "message": "You do not have permission to view this submission."
            }, status=status.HTTP_403_FORBIDDEN)

        serializer = self.get_serializer(instance)
        return Response({
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        """
        Fully update an assignment submission.
        Students can only update their own submissions.
        """
        instance = self.get_object()
        if instance.student != request.user:
            return Response({
                "message": "You do not have permission to update this submission."
            }, status=status.HTTP_403_FORBIDDEN)

        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            "message": "Assignment submission updated successfully.",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def partial_update(self, request, *args, **kwargs):
        """
        Partially update an assignment submission.
        Students can only update their own submissions.
        """
        instance = self.get_object()
        if instance.student != request.user:
            return Response({
                "message": "You do not have permission to update this submission."
            }, status=status.HTTP_403_FORBIDDEN)

        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            "message": "Assignment submission partially updated successfully.",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        """
        Delete an assignment submission.
        Students can only delete their own submissions.
        """
        instance = self.get_object()
        if instance.student != request.user:
            return Response({
                "message": "You do not have permission to delete this submission."
            }, status=status.HTTP_403_FORBIDDEN)

        self.perform_destroy(instance)
        return Response({
            "message": "Assignment submission deleted successfully."
        }, status=status.HTTP_204_NO_CONTENT)


