"""init

Revision ID: 814d7458fd2d
Revises: 
Create Date: 2024-10-02 17:43:35.027243

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '814d7458fd2d'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'keys',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('value', sa.Text, nullable=False),
        sa.Column('userid', sa.Integer, nullable=True),
        sa.Column('created', sa.DateTime, nullable=False),
        sa.Column('expires', sa.DateTime, nullable=False),
        sa.Column('data', sa.Text, nullable=True),
    )


def downgrade() -> None:
    op.drop_table("keys")
