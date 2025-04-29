from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '1cb2b56243f5'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('workflows', sa.Column('schedule', sa.String(), nullable=True))
    op.add_column('workflows', sa.Column('recurrence', sa.String(), nullable=True))

def downgrade():
    op.drop_column('workflows', 'recurrence')
    op.drop_column('workflows', 'schedule')
