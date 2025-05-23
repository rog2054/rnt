"""add theme to User

Revision ID: 72530e0afc68
Revises: 82f11b0842a0
Create Date: 2025-04-21 20:27:20.008088

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '72530e0afc68'
down_revision = '82f11b0842a0'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('theme', sa.String(length=20), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('theme')

    # ### end Alembic commands ###
