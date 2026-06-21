import asyncio

from fastapi import APIRouter
from loguru import logger

from .crud import db
from .tasks import wait_for_paid_invoices
from .views import tagid_generic_router
from .views_api import tagid_api_router
from .views_lnurl import tagid_lnurl_router

tagid_static_files = [
    {
        "path": "/tagid/static",
        "name": "tagid_static",
    }
]

tagid_ext: APIRouter = APIRouter(prefix="/tagid", tags=["tagid"])
tagid_ext.include_router(tagid_generic_router)
tagid_ext.include_router(tagid_api_router)
tagid_ext.include_router(tagid_lnurl_router)

scheduled_tasks: list[asyncio.Task] = []


def tagid_stop():
    for task in scheduled_tasks:
        try:
            task.cancel()
        except Exception as ex:
            logger.warning(ex)


def tagid_start():
    from lnbits.tasks import create_permanent_unique_task

    task = create_permanent_unique_task("ext_tagid", wait_for_paid_invoices)
    scheduled_tasks.append(task)


__all__ = [
    "tagid_ext",
    "tagid_start",
    "tagid_static_files",
    "tagid_stop",
    "db",
]
