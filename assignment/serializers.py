from rest_framework import serializers
from .models import Assignment, AssignmentSubmission, User
from django.contrib.auth.hashers import make_password
import re
from decimal import Decimal

# UserProfileSerializer: View user's profile information
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id',
            'name',
            'email',
            'role',
            'is_active',
            'is_staff',
            'is_superuser',
            'date_joined',
            'last_login',
        ]
        read_only_fields = ['email', 'is_active', 'is_staff', 'is_superuser', 'date_joined', 'last_login']


# SignupSerializer: Handle user registration with password confirmation and validation
class SignupSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['name', 'email', 'password', 'confirm_password', 'role']
        extra_kwargs = {
            'password': {'write_only': True},
            'role': {'required': True},
        }

    def validate_email(self, value):
        """
        Ensure that the email is unique.
        """
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def validate(self, data):
        """
        Validate that the password and confirm_password match, 
        and that the password meets required complexity.
        """
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        password_pattern = r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$"  # At least 8 chars, a number, a lower and upper case letter

        if password != confirm_password:
            raise serializers.ValidationError("Password and Confirm Password do not match.")
        
        if not re.match(password_pattern, password):
            raise serializers.ValidationError(
                "Password must contain at least 8 characters, including one uppercase letter, one lowercase letter, and one digit."
            )
        
        return data
    
    def create(self, validated_data):
        """
        Create a user with validated data and return the user instance.
        """
        name = validated_data.get('name')
        role = validated_data.get('role')
        
        if not name:
            raise serializers.ValidationError("Name is required.")  # Custom validation for missing name
        
        if not role:
            raise serializers.ValidationError("Role is required.")  # Custom validation for missing role

        
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            name=name,
            role=role
        )
        return user


# AssignmentSerializer: Handle assignment data creation and updates
class AssignmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Assignment
        fields = ('id', 'title', 'description', 'file')
        extra_kwargs = {
            'title': {'required': True, 'error_messages': {'required': 'Title is required for an assignment.'}},
            'description': {'required': True, 'error_messages': {'required': 'Description is required for an assignment.'}},
            'file': {'required': True, 'error_messages': {'required': 'File is required for an assignment.'}}
        }

    def validate_title(self, value):
        """
        Ensure that the title of the assignment is not too short.
        """
        if len(value) < 5:
            raise serializers.ValidationError("Title must be at least 5 characters long.")
        return value


# AssignmentSubmissionSerializer: Handle assignment submissions
class AssignmentSubmissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssignmentSubmission
        fields = ('id', 'assignment', 'student', 'submission_file', 'submitted_at')
       
    def validate_submission_file(self, value):
        """
        Validate that the submission file is not empty and is of an acceptable file type.
        """
        if not value.name.endswith(('.jpg', '.png', '.pdf')):
            raise serializers.ValidationError("Only JPG, PNG, and PDF files are allowed for submission.")
        
        return value
