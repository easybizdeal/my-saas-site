"""Add folder_name column to UploadedFile

Revision ID: d9dc13d4aa8b
Revises: 
Create Date: 2025-07-01 09:33:01.154247

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd9dc13d4aa8b'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('uploaded_file', schema=None) as batch_op:
        batch_op.add_column(sa.Column('folder_name', sa.String(length=150), nullable=True))

def downgrade():
    with op.batch_alter_table('uploaded_file', schema=None) as batch_op:
        batch_op.drop_column('folder_name')
