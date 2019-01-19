from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    email = Column(String, nullable=False, unique=True)
    picture = Column(String(250))

    @property
    def serialize(self):
        return { 
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'picture': self.picture
        }

engine = create_engine('sqlite:///catalog.db')
Base.metadata.create_all(engine)
