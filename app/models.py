from sqlalchemy import Column, Integer, BigInteger, String, Float, Text, ForeignKey, Date, DateTime, SmallInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class users(Base):
    __tablename__ = 'users'
    userid = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    passwordhash = Column(String, nullable=False)
    usertype = Column(String, nullable=False)  # Например, "admin", "user"
    
    # Связь с таблицей admin
    admin = relationship('admin', back_populates='user', uselist=False)  # uselist=False указывает на связь 1:1

    listings = relationship('listing', back_populates='user')
    reviews = relationship('review', back_populates='user')
    requests = relationship('purchaserequest', back_populates='user')
    logs = relationship('actionlog', back_populates='user')



class listing(Base):
    __tablename__ = 'listing'
    listingid = Column(BigInteger, primary_key=True, autoincrement=True)
    userid = Column(BigInteger, ForeignKey('users.userid'), nullable=False)
    typeid = Column(Integer, ForeignKey('propertytype.typeid'), nullable=False)
    price = Column(BigInteger, nullable=False)
    address = Column(Text, nullable=False)
    area = Column(Float, nullable=False)
    status = Column(String, nullable=False)  # Например, "available", "sold"

    user = relationship('users', back_populates='listings')
    property_type = relationship('propertytype')
    reviews = relationship('review', back_populates='listing')
    requests = relationship('purchaserequest', back_populates='listing')


class propertytype(Base):
    __tablename__ = 'propertytype'
    typeid = Column(Integer, primary_key=True)
    Typename = Column(String, nullable=False, unique=True)


class review(Base):
    __tablename__ = 'review'
    reviewid = Column(BigInteger, primary_key=True, autoincrement=True)
    userid = Column(BigInteger, ForeignKey('users.userid'), nullable=False)
    listingid = Column(BigInteger, ForeignKey('listing.listingid'), nullable=False)
    rating = Column(SmallInteger, nullable=False)  # Рейтинг 1-10
    reviewtext = Column(Text, nullable=True)
    reviewdate = Column(Date, nullable=False)

    user = relationship('users', back_populates='reviews')
    listing = relationship('listing', back_populates='reviews')


class purchaserequest(Base):
    __tablename__ = 'purchaserequest'
    requestid = Column(BigInteger, primary_key=True, autoincrement=True)
    listingid = Column(BigInteger, ForeignKey('listing.listingid'), nullable=False)
    userid = Column(BigInteger, ForeignKey('users.userid'), nullable=False)
    requestdate = Column(Date, nullable=False)
    requeststatus = Column(String, nullable=False)  # Например, "pending", "approved", "rejected"

    listing = relationship('listing', back_populates='requests')
    user = relationship('users', back_populates='requests')


class admin(Base):
    __tablename__ = 'admin'
    adminid = Column(BigInteger, primary_key=True, autoincrement=True)
    userid = Column(BigInteger, ForeignKey('users.userid'), nullable=False)  # Внешний ключ на users.userid
    adminname = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)

    # Связь с пользователем
    user = relationship('users', back_populates='admin', uselist=False)  # uselist=False для 1:1 связи

class actionlog(Base):
    __tablename__ = 'actionlog'
    logid = Column(BigInteger, primary_key=True, autoincrement=True)
    userid = Column(BigInteger, ForeignKey('users.userid'), nullable=True)
    actiontype = Column(String, nullable=False)  # Например, "create", "update", "delete"
    actiondescription = Column(Text, nullable=True)
    actiontimestamp = Column(DateTime, nullable=False)

    user = relationship('users', back_populates='logs')
