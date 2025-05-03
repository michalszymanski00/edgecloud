from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "2c0dbacc6304"
down_revision = "1cb2b56243f5"
branch_labels = None
depends_on = None

def upgrade() -> None:
    # remove any half-baked enum left from a failed run
    op.execute("DROP TYPE IF EXISTS jobstate CASCADE")

    # single enum instance – will be reused for the column
    jobstate = sa.dialects.postgresql.ENUM(
        "queued", "claimed", "running",
        "succeeded", "failed", "canceled",
        name="jobstate"
    )

    # DO NOT call jobstate.create(); SQLAlchemy will do it once for us

    op.create_table(
        "jobs",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("device_id", sa.String,
                  sa.ForeignKey("devices.id", ondelete="CASCADE"), index=True),
        sa.Column("workflow_id", sa.Integer,
                  sa.ForeignKey("workflows.id", ondelete="CASCADE"), index=True),
        sa.Column("state", jobstate,           # ← use the same object here
                  nullable=False, server_default="queued"),
        sa.Column("payload",  sa.JSON),
        sa.Column("result",   sa.JSON),
        sa.Column("error",    sa.String),
        sa.Column("created_at",  sa.TIMESTAMP(timezone=True),
                  server_default=sa.func.now()),
        sa.Column("claimed_at",  sa.TIMESTAMP(timezone=True)),
        sa.Column("started_at",  sa.TIMESTAMP(timezone=True)),
        sa.Column("finished_at", sa.TIMESTAMP(timezone=True)),
    )
    op.create_index("ix_jobs_device_state", "jobs", ["device_id", "state"])

def downgrade() -> None:
    op.drop_index("ix_jobs_device_state", table_name="jobs")
    op.drop_table("jobs")
    op.execute("DROP TYPE IF EXISTS jobstate CASCADE")
