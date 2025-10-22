from fastapi import APIRouter, status, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session
from helpers.res_ponse import return_response
import schemas.scans as scan_schema
import schemas.users as user_schema
from services.scanners import ScannerService
from logger import logger
from database import get_db
from security import get_current_user
from models import Users, ScanResult
from helpers import format_datetime
from services.vuln_services import VulnServices

scan_router = APIRouter(prefix="/scan", tags=["Scans"])

vuln_services = VulnServices()


@scan_router.post("/scans", response_model=scan_schema.ApiResponse)
async def create_scan(
    scan_data: scan_schema.ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user),
):
    try:
        url = scan_data.url
        swagger_url = scan_data.doc_url
        scan_types = scan_data.scan_types

        res = vuln_services.check_valid_doc(swagger_url)
        if not res:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Documentation URL",
            )

        user_id = current_user.id

        background_tasks.add_task(
            vuln_services._start,
            url,
            swagger_url,
            scan_types,
            user_id,
        )

        return scan_schema.ApiResponse(
            msg="Scan started successfully",
            data={"scan_id": ""},
        )
    except HTTPException as http_exc:
        logger.info(f"Create Scan exception: {http_exc}")
        raise http_exc
    except Exception as e:
        logger.exception(f"Create Scan exception")
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Network Error"
        )


@scan_router.get("/scans/{scan_id}", response_model=user_schema.APIResponse)
async def get_scan_result(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user),
):
    """Get scan results by ID"""
    scanner_service = ScannerService()
    scan_record = scanner_service.get_scan_status(scan_id, current_user.id)

    if not scan_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )

    return user_schema.APIResponse(
        msg="Scan retrieved successfully",
        data=scan_schema.ScanResultResponse.model_validate(scan_record),
    )


@scan_router.get("/scans", response_model=user_schema.APIResponse)
async def list_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user),
):
    """List recent scans"""
    scanner_service = ScannerService()
    scans = await scanner_service.get_all_user_scans(
        page=page, per_page=per_page, user_id=current_user.id
    )
    total = db.query(ScanResult).filter(ScanResult.user_id == current_user.id).count()

    return user_schema.APIResponse(
        msg="Scans retrieved successfully",
        data=[scan_schema.ScanResultResponse.model_validate(scan) for scan in scans],
        pagination={
            "total_items": total,
            "page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page,
        },
    )


@scan_router.get("/stats", response_model=user_schema.APIResponse)
async def get_scan_stats(
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user),
):
    """Get scan stats"""
    scanner_service = ScannerService()
    stats = await scanner_service.get_user_scan_stats(current_user.id)
    return user_schema.APIResponse(
        msg="Scan stats retrieved successfully",
        data=stats,
    )
