# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.shortcuts import render, redirect
from django.db.models import Value
from django.db.models.functions import Concat
from models import *
from django.contrib import messages
import bcrypt
import re

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

def index(request):
    return render(request, "user_dash/index.html")

def registration(request):
    error = False
    if request.method == "POST":
        try: 
            len(User.objects.get(email=request.POST['email'])) > 0
        except Exception:
            messages.error(request, "Error occured, check again")
        if len(request.POST['first_name']) < 1 or len(request.POST['last_name']) < 1:
            messages.error(request, "Name field required")
            error = True
        if not EMAIL_REGEX.match(request.POST['email']):
            messages.error(request, "Invalid email")
            error = True
        if request.POST['password'] != request.POST['conf_pass']:
            messages.error(request, "Passwords don't match")
            error = True
        if error:
            messages.error(request, "All fields required")
            return redirect('/register')
        else:
            hash_pw = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
            user = User.objects.create(email=request.POST['email'], first_name=request.POST['first_name'], last_name=request.POST['last_name'], password=hash_pw)
            user = User.objects.first()
            if len(User.objects.all()) == 1:
                user.auth_level = 9
                user.save()
                request.session['id'] = user.id
                return redirect('/dashboard/admin')
            else:
                request.session['id'] = user.id
                return redirect('/dashboard')
    else:
        return redirect('/')

def register(request):
    return render(request, 'user_dash/register.html')

def login(request):
    if request.method == "POST":
        retrieved_users = User.objects.filter(email=request.POST['email'])
        if len(retrieved_users) > 0:
            retrieved_user = retrieved_users[0]
            request.session['id'] = retrieved_user.id
        if bcrypt.checkpw(request.POST['password'].encode(), retrieved_user.password.encode()):
            if retrieved_user.auth_level == 0:
                return redirect('/dashboard')
            else:
                return redirect('/dashboard/admin')
    else:
        return redirect('/')

def dashboard(request):
    if not 'id' in request.session:
        return redirect('/')
    user = User.objects.get(id=request.session['id'])
    if user.auth_level == 9:
        return redirect('/dashboard/admin')
    context = {
        "users": User.objects.all(),
    }
    return render(request, 'user_dash/dashboard.html', context)

def dashboard_admin(request):
    if not 'id' in request.session:
        return redirect('/')
    user = User.objects.get(id=request.session['id'])
    if user.auth_level == 0:
        return redirect('/dashboard')
    context = {
        "users": User.objects.all(),
    }
    return render(request, 'user_dash/dashboard_admin.html', context)

def add_new(request):
    user = User.objects.get(id=request.session['id'])
    if user.auth_level == 0:
        auth = True
        request.session['auth'] = auth
        return redirect('/dashboard')
    return render(request, 'user_dash/add.html')

def add(request):
    if request.method == "POST":
        error = False
        if len(User.objects.filter(email=request.POST['email'])) > 0:
            messages.error(request, "Error has occured")
            error = True
        if len(request.POST['first_name']) < 1 or len(request.POST['last_name']) < 1:
            messages.error(request, "Name field required")
            error = True
        if not EMAIL_REGEX.match(request.POST['email']):
            messages.error(request, "Invalid email")
            error = True
        if request.POST['password'] != request.POST['conf_pass']:
            messages.error(request, "Passwords don't match")
            error = True
        if error:
            messages.error(request, "All fields required")
            return redirect('/register')
        else:
            hash_pw = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
            user = User.objects.create(email=request.POST['email'], first_name=request.POST['first_name'], last_name=request.POST['last_name'], password=hash_pw)
            return redirect('/dashboard/admin')
    else:
        return redirect('/dashboard/admin')

def show(request, user_id):
    user = User.objects.get(id=user_id)
    post = Post.objects.filter(created_by=User.objects.get(id=user_id))
    context = {
        "users": user,
        "posts": post
    }
    return render(request, 'user_dash/show.html', context)

def post(request, user_id):
    if request.method == "POST":
        post = Post.objects.create(post=request.POST['post'], created_by=User.objects.get(id=user_id))
        return redirect('/users/show/{}'.format(user_id))
    else:
        user = User.objects.get(id=user_id)
        if user.auth_level == 9:
            return redirect('/dashboard/admin')
        else:
            return redirect('/dashboard')

def edit(request, user_id):
    user = User.objects.get(id=user_id)
    context = {
        "users": user
    }
    return render(request, 'user_dash/edit.html', context)

def edit_user(request, user_id):
    if request.method == "POST":
        if request.POST['email']:
            user = User.objects.get(id=user_id)
            user.email = request.POST['email']
            user.first_name = request.POST['first_name']
            user.last_name = request.POST['last_name']
            user.auth_level = request.POST['auth_level']
            user.save()
            messages.success(request, "User has been updated")
            return redirect('/users/edit/{}'.format(user_id))
        # if request.POST['email'] is None:
        #     pass

#Need help with this

        if request.POST['password']:
            hash_pw = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
            if request.POST['password'] != request.POST['conf_pass']:
                messages.error(request, "Passwords don't match!")
                return redirect('/users/edit/{}'.format(user_id))
            user.password = hash_pw
            user.save()
            messages.success(request, "Password has been updated")
            return redirect('/users/edit/{}'.format(user_id))
        else:
            messages.error(request, "Fields are required")
            return redirect('/users/edit/{}'.format(user_id))
    else:
        return redirect('/users/edit/{}'.format(user_id))

def logout(request):
    request.session.clear()
    return redirect('/')

def profile(request, user_id):
    return render(request, 'user_dash/profile.html')

def edit_profile(request, user_id):
    if request.method == "POST":
        user = User.objects.get(id=user_id)
        if request.POST['email']:
            user.email = request.POST['email']
            user.first_name = request.POST['first_name']
            user.last_name = request.POST['last_name']
            user.auth_level = request.POST['auth_level']
            user.save()
            messages.success(request, "User has been updated")
            return redirect('/users/profile/{}'.format(user_id))
        if request.POST['password']:
            hash_pw = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
            if request.POST['password'] != request.POST['conf_pass']:
                messages.error(request, "Passwords don't match!")
                return redirect('/users/profile/{}'.format(user_id))
            user.password = hash_pw
            user.save()
            messages.success(request, "Password has been updated")
            return redirect('/users/profile/{}'.format(user_id))
        if request.POST['desc']:
            user.desc = request.POST['desc']
            return redirect('/dashboard')
    else:
        return redirect('/dashboard')