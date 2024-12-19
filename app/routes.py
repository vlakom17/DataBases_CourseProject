from . models import users, listing, review, purchaserequest, admin, actionlog, propertytype
from flask import render_template
from . database import get_db, db
from . auth import hash_password, verify_password
from . utils import generate_token
from pydantic import BaseModel, ValidationError
from typing import List
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from functools import wraps
from typing import Optional
from flask import request, jsonify, abort
from config import Config
from datetime import datetime
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash

ALGORITHM = "HS256"

def log_action(
    db: Session,
    action_type: str,
    action_description: str,
    user_id: int,
):
    log_entry = actionlog(
        userid=user_id,
        actiontype=action_type,
        actiondescription=action_description,
        actiontimestamp=datetime.utcnow(),
    )

    db.add(log_entry)  # Добавляем запись в сессию
    db.commit()  # Подтверждаем изменения в базе данных

def is_admin_user(current_user):
    if not current_user or current_user.usertype != "admin":
        raise PermissionError("Operation not permitted")
    return current_user


def get_current_user_from_request(request, db: Session):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None

    token = auth_header.split(" ")[1]

    try:
        payload = jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
        email = payload.get("sub")
        if not email:
            return None

        user = db.query(users).filter(users.email == email).first()
        return user
    except JWTError:
        return None
    
def object_as_dict(obj):
    
    return {c.key: getattr(obj, c.key) for c in inspect(obj).mapper.column_attrs}

init_bp = Blueprint('init', __name__)

@init_bp.route("/")
def index():
    return render_template("index.html")

@init_bp.route('/register/')
def register():
    return render_template('register.html')

@init_bp.route('/login/')
def login():
    return render_template('login.html')

@init_bp.route('/listings/')
def listings():
    return render_template('listings.html')

@init_bp.route('/listings-create/')
def listings_create():
    return render_template('listings-create.html')

@init_bp.route('/logout-confirm/')
def logout_confirm():
    return render_template("logout-confirm.html")

@init_bp.route('/listing-management/<int:listing_id>/')
def listing_management(listing_id):
    return render_template("listing-management.html", listing_id=listing_id)

@init_bp.route('/listings-edit/<int:listing_id>/')
def listings_edit(listing_id):
    return render_template("listings-edit.html", listing_id=listing_id)

@init_bp.route('/purchase-requests/')
def purchase_requests():
    return render_template("purchase-requests.html")

@init_bp.route('/update-request/<int:request_id>/')
def update_request(request_id):
    return render_template("update-request.html", request_id=request_id)

@init_bp.route('/listing-reviews/<int:listing_id>/')
def listing_reviews(listing_id):
    return render_template("listing-reviews.html", listing_id=listing_id)

@init_bp.route('/edit-review/<int:review_id>/')
def edit_review(review_id):
    return render_template("edit-review.html", review_id=review_id)


@init_bp.route('/update-user/<int:user_id>/')
def update_user(user_id):
    return render_template("update-user.html", user_id=user_id)

auth_bp = Blueprint('auth', __name__)

@auth_bp.route("/api-register/", methods=["POST"])
def register_user():
    data = request.get_json()
    if not data or not all(key in data for key in ("name", "email", "password")):
        return jsonify({"message": "Invalid request"}), 400

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    # Проверяем, существует ли пользователь
    existing_user = db.session.query(users).filter(users.email == email).first()
    if existing_user:
        return jsonify({"message": "email already registered"}), 400

    # Хэшируем пароль
    hashed_password = hash_password(password)
    new_user = users(
        name=name,
        email=email,
        passwordhash=hashed_password,
        usertype='user'  # Устанавливаем роль по умолчанию
    )

    db.session.add(new_user)
    db.session.commit()
    db.session.refresh(new_user)

    # Генерируем токен
    access_token = generate_token(data={"sub": new_user.email}, secret_key="YOUR_SECRET_KEY")

    # Логирование регистрации пользователя
    log_action(
        db=db.session,
        action_type="register",
        action_description=f"New user registered with email: {email}",
        user_id=new_user.userid
    )

    return jsonify({"access_token": access_token, "token_type": "bearer"}), 201

@auth_bp.route("/api-login/", methods=["POST"])
def login_user():
    data = request.get_json()
    if not data or not all(key in data for key in ("email", "password")):
        return jsonify({"message": "Invalid request"}), 400

    email = data.get("email")
    password = data.get("password")

    # Проверяем, существует ли пользователь
    user = db.session.query(users).filter(users.email == email).first()
    if not user or not verify_password(user.passwordhash, password):
        return jsonify({"message": "Invalid email or password"}), 401

    # Генерируем токен
    access_token = generate_token(data={"sub": user.email, "user_id": user.userid}, secret_key=Config.SECRET_KEY)
    
    # Логирование входа пользователя
    log_action(
        db=db.session,
        action_type="login",
        action_description=f"User {user.userid} logged in.",
        user_id=user.userid
    )

    return jsonify({"access_token": access_token, "token_type": "bearer"}), 200

@auth_bp.route("/api-logout/", methods=["POST"])
def logout_user():
    db_session: Session = db.session
    current_user = get_current_user_from_request(request, db_session)
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None

    token = auth_header.split(" ")[1]

    if not current_user:
        return jsonify({"detail": "User not logged in"}), 401

    log_action(
        db=db_session,
        action_type="logout",
        action_description=f"User {current_user.userid} logged out.",
        user_id=current_user.userid
    )
    token = "xxx"
    return jsonify({"detail": "Successfully logged out"}), 200

usr_bp = Blueprint('usr', __name__)

@usr_bp.route("/users/update-role/", methods=["PUT"])
def update_user_role():
    data = request.get_json()
    new_role = data.get("new_role")
    secret_key = data.get("secret_key")
    db: Session = get_db()

    # Проверка наличия SECRET_KEY и его валидности
    if secret_key != Config.SECRET_KEY:
        return jsonify({"message": "Invalid SECRET_KEY"}), 403

    # Получаем текущего пользователя из токена
    current_user = get_current_user_from_request(request, db)
    if not current_user:
        return jsonify({"message": "User not found"}), 404

    if new_role not in ["user", "admin"]:
        return jsonify({"message": "Invalid role"}), 400

    previous_role = current_user.usertype

    # Если роль изменяется с "admin" на другую - удаляем запись из таблицы admin
    if previous_role == "admin" and new_role != "admin":
        admin_entry = db.query(admin).filter(admin.userid == current_user.userid).first()
        if admin_entry:
            db.delete(admin_entry)

    # Если роль изменяется на "admin" - добавляем запись в таблицу admin
    if new_role == "admin" and previous_role != "admin":
        admin_entry = db.query(admin).filter(admin.userid == current_user.userid).first()
        if not admin_entry:
            new_admin_entry = admin(
                userid=current_user.userid,
                adminname=current_user.name,
                email=current_user.email
            )
            db.add(new_admin_entry)

    # Обновляем роль в таблице users
    current_user.usertype = new_role
    db.commit()

    # Логирование изменения роли пользователя
    log_action(
        db=db,
        action_type="update_role",
        action_description=f"User {current_user.userid} updated their role from {previous_role} to {new_role}",
        user_id=current_user.userid
    )

    return jsonify({"detail": f"User role updated to {new_role}"}), 200

@usr_bp.route('/users/me/', methods=['GET'])
def get_current_user_info():

    db: Session = get_db()
    
    # Получаем текущего пользователя из токена
    current_user = get_current_user_from_request(request, db)
    
    if not current_user:
        return jsonify({"message": "User not found"}), 404
    
    # Формируем ответ с информацией о пользователе
    user_data = {
        "userid": current_user.userid,
        "name": current_user.name,
        "email": current_user.email,
        "role": current_user.usertype
    }
    
    return jsonify(user_data), 200

# Определение модели для данных запроса
class UpdateUsername(BaseModel):
    name: str

@usr_bp.route("/users/update-name/", methods=["PUT"])
def update_user_name():
    # Получаем данные из запроса
    update_data = UpdateUsername(**request.json)  # Предполагаем, что тело запроса - это JSON

    db: Session = get_db()

    # Получаем текущего пользователя
    current_user = get_current_user_from_request(request, db)

    # Сохраняем старое имя для логирования
    old_name = current_user.name
    
    # Обновляем имя пользователя
    current_user.name = update_data.name
    db.commit()
    db.refresh(current_user)
    
    # Логирование изменения имени
    log_action(
        db=db,
        action_type="update",
        action_description=f"User {current_user.userid} updated their name from '{old_name}' to '{current_user.name}'",
        user_id=current_user.userid
    )
    
    return jsonify({"detail": "User name updated successfully", "new_name": current_user.name}), 200



# Создаем Blueprint для маршрутов listings
list_bp = Blueprint('list', __name__)


class listingCreate(BaseModel):
    typeid: int
    price: float
    address: str
    area: float
    status: str

@list_bp.route("/create-listings/", methods=["POST"])
def create_listing():
    db: Session = get_db()  # Получаем сессию базы данных
    current_user = get_current_user_from_request(request, db)  # Получаем текущего пользователя

    # Валидация данных с помощью pydantic
    listing_data = listingCreate(**request.json)

    new_listing = listing(
        userid=current_user.userid,
        typeid=listing_data.typeid,
        price=listing_data.price,
        address=listing_data.address,
        area=listing_data.area,
        status=listing_data.status
    )

    db.add(new_listing)
    db.commit()
    db.refresh(new_listing)

    # Логируем создание объявления
    log_action(
        db=db,
        action_type="create",
        action_description=f"User {current_user.userid} created a listing with ID {new_listing.listingid}",
        user_id=current_user.userid,
    )

    return jsonify(listing_data.dict()), 201

@list_bp.route("/all-listings/", methods=["GET"])
def get_listings():
    current_user = get_current_user_from_request(request, db.session)
    
    if not current_user:
        return jsonify({"error": "User not authenticated"}), 401

    db_session: Session = db.session

    try:
        # Получение всех объектов из базы данных
        listings = db_session.query(listing).all()

        # Преобразуем данные в формат JSON
        listings_data = [object_as_dict(listing) for listing in listings]

        return jsonify({
            "listings": listings_data,
            "total_count": len(listings_data)  # Общее количество объявлений
        }), 200

    except Exception as e:
        return jsonify({"error": "An internal error occurred. Please try again later."}), 500


@list_bp.route("/api-listings/<int:listing_id>/", methods=["GET"])
def get_listing_by_id(listing_id):
    current_user = get_current_user_from_request(request, db.session)
    
    if not current_user:
        return jsonify({"error": "User not authenticated"}), 401

    db_session: Session = db.session

    try:
        # Получение объявления по его ID
        listing_item = db_session.query(listing).filter(listing.listingid == listing_id).first()

        if not listing_item:
            return jsonify({"error": "Listing not found"}), 404

        # Преобразуем данные в формат JSON
        listing_data = object_as_dict(listing_item)

        return jsonify({
            "listing": listing_data
        }), 200

    except Exception as e:
        return jsonify({"error": "An internal error occurred. Please try again later."}), 500


@list_bp.route("/api-listings/<int:listing_id>/", methods=["DELETE"])
def delete_listing(listing_id):
    db: Session = get_db()  # Получаем сессию базы данных
    current_user = get_current_user_from_request(request, db)

    try:
        admin = is_admin_user(current_user)  # Проверяем, является ли текущий пользователь администратором
    except PermissionError as e:
        return jsonify({"message": str(e)}), 403

    listing_item = db.query(listing).filter(listing.listingid == listing_id).first()
    if not listing_item:
        return jsonify({"detail": "Listing not found"}), 404

    db.delete(listing_item)
    db.commit()

    log_action(
        db=db,
        action_type="delete",
        action_description=f"User {admin.userid} deleted a listing with ID {listing_id}",
        user_id=admin.userid,
    )

    return jsonify({"detail": "Listing deleted"}), 200


class Updatelisting(BaseModel):
    address: Optional[str]
    area: Optional[float]
    price: Optional[float]
    status: Optional[str]
    typeid: Optional[int]


@list_bp.route("/api-listings/<int:listing_id>/", methods=["PUT"])
def update_listing(listing_id):
    db: Session = get_db()  # Получаем сессию базы данных
    current_user = get_current_user_from_request(request, db)  # Получаем текущего пользователя

    # Получаем данные из запроса
    request_data = request.json

    # Попытка валидировать входные данные
    try:
        update_data = Updatelisting(**request_data)
    except ValidationError as e:
        return jsonify({"error": e.errors()}), 400

    # Поиск записи в базе данных
    listing_item = db.query(listing).filter(listing.listingid == listing_id, listing.userid == current_user.userid).first()
    
    if not listing_item:
        return jsonify({"detail": "listing not found or you are not authorized to update this listing"}), 404

    # Обновление полей объявления только с учётом переданных данных
    update_fields = update_data.dict(exclude_unset=True)
    for field, value in update_fields.items():
        setattr(listing_item, field, value)

    db.commit()
    db.refresh(listing_item)

    # Логирование действия
    log_action(
        db=db,
        action_type="update",
        action_description=f"User {current_user.userid} updated a listing with ID {listing_id}",
        user_id=current_user.userid,
    )

    # Возврат обновлённого объекта
    return jsonify({
        "detail": "listing updated successfully",
        "listing": {
            "listingid": listing_item.listingid,
            "typeid": listing_item.typeid,
            "price": listing_item.price,
            "address": listing_item.address,
            "area": listing_item.area,
            "status": listing_item.status,
        }
    }), 200



# Создаем Blueprint для маршрутов purchase requests
pr_bp = Blueprint('purchase_requests', __name__)

class purchaserequestCreate(BaseModel):
    listingid: int


@pr_bp.route("/purchaserequests/", methods=["POST"])
def create_purchase_request():
    db: Session = get_db()  # Получаем сессию базы данных
    current_user = get_current_user_from_request(request, db)  # Получаем текущего пользователя

    # Получаем данные для создания запроса на покупку из запроса
    request_data = purchaserequestCreate(**request.json)

    # Проверяем, что объявление существует
    listing_item = db.query(listing).filter(listing.listingid == request_data.listingid).first()
    if not listing_item:
        return jsonify({"detail": "listing not found"}), 404
    
    # Проверяем, что пользователь не является владельцем объявления
    if listing_item.userid == current_user.userid:
        return jsonify({"detail": "You cannot request to purchase your own listing"}), 400
    
    # Создаем запрос на покупку
    new_request = purchaserequest(
        listingid=request_data.listingid,
        userid=current_user.userid,
        requestdate=datetime.utcnow(),
        requeststatus="Pending"
    )
    db.add(new_request)
    db.commit()
    db.refresh(new_request)

    # Логируем создание запроса на покупку
    log_action(
        db=db,
        action_type="create",
        action_description=f"User {current_user.userid} created a purchase request for listing {request_data.listingid}",
        user_id=current_user.userid
    )

    return jsonify({"detail": "Purchase request created successfully", "request": object_as_dict(new_request)}), 201

@pr_bp.route("/purchaserequests/<int:request_id>/", methods=["GET"])
def get_purchase_request(request_id: int):
    db: Session = get_db()  # Получаем сессию базы данных
    current_user = get_current_user_from_request(request, db)  # Получаем текущего пользователя

    # Ищем запрос на покупку по его ID и проверяем, что он принадлежит текущему пользователю
    request_item = db.query(purchaserequest).filter(purchaserequest.requestid == request_id, purchaserequest.userid == current_user.userid).first()

    # Если запрос не найден
    if not request_item:
        return jsonify({"detail": "Purchase request not found for this user"}), 404

    # Логируем доступ пользователя к его запросу
    log_action(
        db=db,
        action_type="read",
        action_description=f"User {current_user.userid} accessed purchase request {request_id}",
        user_id=current_user.userid
    )

    # Преобразуем объект запроса в словарь
    request_dict = object_as_dict(request_item)

    # Возвращаем запрос в формате JSON
    return jsonify({"request": request_dict}), 200


@pr_bp.route("/purchaserequests/", methods=["GET"])
def get_user_purchase_requests():
    db: Session = get_db()  # Получаем сессию базы данных
    current_user = get_current_user_from_request(request, db)  # Получаем текущего пользователя

    # Получаем все запросы текущего пользователя
    requests = db.query(purchaserequest).filter(purchaserequest.userid == current_user.userid).all()

    # Если у пользователя нет запросов
    if not requests:
        return jsonify({"detail": "No purchase requests found for this user"}), 404

    # Логируем доступ пользователя к его запросам
    log_action(
        db=db,
        action_type="read",
        action_description=f"User {current_user.userid} accessed their purchase requests",
        user_id=current_user.userid
    )

    # Преобразуем каждый объект в словарь
    requests_dict = [object_as_dict(request) for request in requests]

    # Возвращаем список запросов в формате JSON
    return jsonify({"requests": requests_dict}), 200


class purchaserequestUpdate(BaseModel):
    requeststatus: str  # "pending", "approved", "rejected"


@pr_bp.route("/purchaserequests/<int:request_id>/", methods=["PUT"])
def update_purchase_request_status(request_id: int):
    db: Session = get_db()  # Получаем сессию базы данных

    # Проверяем, что запрос на покупку существует
    purrequest = db.query(purchaserequest).filter(purchaserequest.requestid == request_id).first()
    if not purrequest:
        return jsonify({"detail": "Purchase request not found"}), 404  # Возвращаем 404 Not Found

    # Получаем данные обновления статуса из запроса
    update_data = purchaserequestUpdate(**request.json)

    # Проверяем корректность статуса
    if update_data.requeststatus not in ["Pending", "Approved", "Rejected"]:
        return jsonify({"detail": "Invalid request status"}), 400  # Возвращаем 400 Bad Request
    
    # Получаем текущего пользователя
    current_user = get_current_user_from_request(request, db)

    # Проверяем, что текущий пользователь — это тот, кто подал запрос на покупку
    if purrequest.userid != current_user.userid:
        return jsonify({"detail": "You can only update your own purchase request"}), 403  # Возвращаем 403 Forbidden

    # Обновляем статус
    old_status = purrequest.requeststatus
    purrequest.requeststatus = update_data.requeststatus
    db.commit()
    db.refresh(purrequest)

    # Логируем обновление статуса
    log_action(
        db=db,
        action_type="update",
        action_description=f"User {current_user.userid} changed status of purchaserequest {request_id} from {old_status} to {update_data.requeststatus}",
        user_id=current_user.userid
    )

    return jsonify({"detail": "Purchase request status updated", "request": object_as_dict(purrequest)}), 200  # Возвращаем 200 OK


# Создаем Blueprint
rvi_bp = Blueprint('reviews', __name__)

class reviewBase(BaseModel):
    listingid: int
    rating: int  # Рейтинг от 1 до 10
    reviewtext: Optional[str] = None

class reviewResponse(reviewBase):
    reviewid: int
    userid: int
    reviewdate: str


@rvi_bp.route("/reviews/", methods=["POST"])
def create_review():
    data = request.get_json()

    try:
        # Валидация входных данных с помощью Pydantic
        validated_data = reviewBase(**data)
    except ValueError as e:
        return jsonify({"detail": str(e)}), 400  # 400 Bad Request

    db: Session = get_db()
    current_user = get_current_user_from_request(request, db)  # Получение текущего пользователя

    # Проверяем, что объявление существует
    listing_item = db.query(listing).filter(listing.listingid == validated_data.listingid).first()
    if not listing_item:
        return jsonify({"detail": "Listing not found"}), 404  # 404 Not Found

    # Создаем новый отзыв
    new_review = review(  # Используйте имя вашей SQLAlchemy модели
        userid=current_user.userid,
        listingid=validated_data.listingid,
        rating=validated_data.rating,
        reviewtext=validated_data.reviewtext,
        reviewdate=datetime.utcnow().date()
    )

    try:
        db.add(new_review)
        db.commit()
        db.refresh(new_review)
    except IntegrityError:
        db.rollback()
        return jsonify({"detail": "Error creating review"}), 400  # 400 Bad Request

    # Логируем действие
    log_action(
        db=db,
        action_type="create",
        action_description=f"User {current_user.userid} created a review for listing {validated_data.listingid}",
        user_id=current_user.userid
    )

    # Создаем объект ответа
    response_data = reviewResponse(
        reviewid=new_review.reviewid,
        userid=new_review.userid,
        listingid=new_review.listingid,
        rating=new_review.rating,
        reviewtext=new_review.reviewtext,
        reviewdate=new_review.reviewdate.isoformat()
    )

    return jsonify(response_data.dict()), 201  # 201 Created


@rvi_bp.route("/reviews/", methods=["GET"])
def get_reviews():
    listing_id = request.args.get('listingid', type=int)  # Получаем параметр listingid из запроса
    db: Session = get_db()

    if listing_id is None:
        return jsonify({"error": "Missing listingid parameter"}), 400

    reviews = db.query(review).filter(review.listingid == listing_id).all()

    # Формируем данные для ответа
    response_data = [
        {
            "reviewid": review.reviewid,
            "userid": review.userid,
            "listingid": review.listingid,
            "rating": review.rating,
            "reviewtext": review.reviewtext,
            "reviewdate": review.reviewdate.isoformat(),
        }
        for review in reviews
    ]

    return jsonify(response_data), 200


@rvi_bp.route("/reviews/<int:review_id>/", methods=["GET"])
def get_review(review_id):
    db: Session = get_db()  # Получаем сессию базы данных
    current_user = get_current_user_from_request(request, db)  # Получаем текущего пользователя

    review_item = db.query(review).filter(review.reviewid == review_id).first()
    if not review_item:
        abort(404, description="Review not found")

    # Логирование доступа к отзыву
    log_action(
        db=db,
        action_type="read",
        action_description=f"User {current_user.userid} read review {review_id}",
        user_id=current_user.userid
    )

    # Проверяем, что поле reviewdate является объектом datetime
    review_date = (
        review_item.reviewdate.isoformat()
        if isinstance(review_item.reviewdate, datetime)
        else review_item.reviewdate
    )

    return jsonify({
        "reviewid": review_item.reviewid,
        "userid": review_item.userid,
        "listingid": review_item.listingid,
        "rating": review_item.rating,
        "reviewtext": review_item.reviewtext,
        "reviewdate": review_date  # Форматированное значение
    }), 200  # 200 OK

class reviewUpdate(BaseModel):
    rating: Optional[int] = None
    reviewtext: Optional[str] = None

@rvi_bp.route("/reviews/<int:review_id>/", methods=["PUT"])
def update_review(review_id):
    db: Session = get_db()  # Получаем сессию базы данных
    current_user = get_current_user_from_request(request, db)  # Получаем текущего пользователя

    review_data = request.get_json()  # Получаем данные отзыва из запроса

    # Найти отзыв, который нужно обновить
    review_item = db.query(review).filter(
        review.reviewid == review_id, 
        review.userid == current_user.userid
    ).first()

    if not review_item:
        abort(404, description="Review not found or not authorized to update")

    # Обновление полей отзыва
    if 'rating' in review_data and review_data['rating'] is not None:
        review_item.rating = review_data['rating']
    if 'reviewtext' in review_data and review_data['reviewtext'] is not None:
        review_item.reviewtext = review_data['reviewtext']

    db.commit()
    db.refresh(review_item)

    # Логирование действия обновления
    log_action(
        db=db,
        action_type="update",
        action_description=f"User {current_user.userid} updated review {review_id}",
        user_id=current_user.userid
    )

    # Проверка формата даты
    review_date = (
        review_item.reviewdate.isoformat()
        if isinstance(review_item.reviewdate, datetime)
        else review_item.reviewdate
    )

    # Формирование ответа
    return jsonify({
        "reviewid": review_item.reviewid,
        "userid": review_item.userid,
        "listing_id": review_item.listingid,
        "rating": review_item.rating,
        "reviewtext": review_item.reviewtext,
        "reviewdate": review_date  # Убедимся, что корректный формат даты
    }), 200  # 200 OK

@rvi_bp.route("/reviews/<int:review_id>/", methods=["DELETE"])
def delete_review(review_id):
    db: Session = get_db()  # Получаем сессию базы данных
    current_user = get_current_user_from_request(request, db)  # Получаем текущего пользователя

    # Поиск отзыва для текущего пользователя
    review_item = db.query(review).filter(review.reviewid == review_id, review.userid == current_user.userid).first()
    
    if not review_item:
        abort(404, description="review not found or not authorized to delete")

    # Удаление отзыва из базы данных
    db.delete(review_item)
    db.commit()

    # Логирование действия
    log_action(
        db=db,
        action_type="delete",
        action_description=f"User {current_user.userid} deleted review {review_id}",
        user_id=current_user.userid
    )

    return jsonify({"detail": "review deleted"}), 200  # Код ответа 200 OK
