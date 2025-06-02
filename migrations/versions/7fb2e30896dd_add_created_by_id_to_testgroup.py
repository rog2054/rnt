"""add created_by_id to TestGroup

Revision ID: 7fb2e30896dd
Revises: e9dd9d26241e
Create Date: 2025-05-22 16:54:55.641467

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7fb2e30896dd'
down_revision = 'e9dd9d26241e'
branch_labels = None
depends_on = None


def upgrade():
    # Step 1: Add column and foreign key
    with op.batch_alter_table('test_group', schema=None) as batch_op:
        batch_op.add_column(sa.Column('created_by_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key('fk_testgroup_created_by_id', 'user', ['created_by_id'], ['id'])

    # Step 2: Update existing rows and set non-nullable
    op.execute("UPDATE test_group SET created_by_id = 1")
    with op.batch_alter_table('test_group', schema=None) as batch_op:
        batch_op.alter_column('created_by_id', nullable=False)

def downgrade():
    with op.batch_alter_table('test_group', schema=None) as batch_op:
        batch_op.drop_constraint('fk_testgroup_created_by_id', type_='foreignkey')
        batch_op.drop_column('created_by_id')

    # ### end Alembic commands ###
