from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, Recipe, User

engine = create_engine('sqlite:///categoryrecipeswithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create categories
categories = ["Snacks","Salads","Appetizers & Sides","Mains","Desserts"]

for category in categories:
	new_category = Category(name=category)
	session.add(new_category)
	session.commit()

print "done"
