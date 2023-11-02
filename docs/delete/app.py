from fastapi import FastAPI, Body, Depends, Query, Request, Path
from fastapi.responses import JSONResponse
from docs.db import *
from docs.security import *
from sqlalchemy import func, alias


app = FastAPI()


@app.post("/login")
def login(email_id:str=Body(...),password:str=Body(...)):
    with database_client.Session() as session:
        employee_data = session.query(
            Employee
        ).filter(
            Employee.email_id == email_id
        ).first()

        if not employee_data:
            _content = {"meta":{"successful":False,"error":{"error_message":"invalid credentials"},},"data":None}
            return JSONResponse(status_code=403, content=_content)
        
        employee_data = employee_data.to_dict()

        banking_info = session.query(
            CompanyBankingInfo
        ).filter(
            CompanyBankingInfo.company_id == employee_data.get("company",{}).get("company_id",{})
        ).order_by(
            CompanyBankingInfo.update_date.desc()
        ).first()

        employee_data["company"]["banking_info"] = banking_info.to_dict() if banking_info else None

    _content, status_code = {"meta":{"successful":False,"error":{"error_message":"invalid credentials"},},"data":None}, 403
    if employee_data.get("password") == password:
        _token = generateJwtToken(exp=100000,user_id=employee_data.get("public_id"),company_id=employee_data.get("company",{}).get("public_id"),role_id=employee_data.get("role",{}).get("public_id"))
        _content, status_code = {"meta":{"successful":True,"error":None,"token":_token},"data":employee_data}, 200
    return JSONResponse(status_code=status_code, content=_content)
    

# Get Logs
@app.get("/logs")
def logs(*,
    company_id:str=Query(...), # all / company_id
    status_filter:str=Query(...), # success, all, failure, issue
    service_filter:str=Query(...), # face_comparison , all , passive_liveness
    start_datetime:datetime.datetime = Query(...),
    end_datetime:datetime.datetime = Query(...),
    page_no:int= Query(1),
    items_per_page:int= Query(15),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request
):
    with database_client.Session() as session:

        log_data = session.query(
            NFaceLogs,
        )

        if company_id != "all":
            log_data = log_data.join(Company, Company.company_id == NFaceLogs.company_id).filter(Company.public_id == company_id)

        if status_filter != "all":
            log_data = log_data.join(
                StatusMaster,
                StatusMaster.status_id == NFaceLogs.status_id
            ).filter(StatusMaster.status == status_filter.upper().strip())


        if service_filter != "all":
            log_data = log_data.join(
                ServiceMaster,
                ServiceMaster.service_id == NFaceLogs.service_id
            ).filter(ServiceMaster.service_name == service_filter.upper().strip())


        log_data = log_data.filter(NFaceLogs.create_date >= start_datetime,
                                NFaceLogs.create_date <= end_datetime)
        
        
        total_count = log_data.with_entities(func.count()).scalar()

        # Pagination
        offset = (page_no - 1) * items_per_page
        log_data = log_data.offset(offset).limit(items_per_page)

        if log_data:
            log_data = log_data.all()
            log_data = [ ld.to_dict() for ld in log_data ]


    _content = {"meta":{"successful":True,"error":None,"pagination_data":{"items_per_page": items_per_page,"page_no": page_no,"total_count": total_count, "page_url": request.url._url}},"data":log_data}
    return JSONResponse(status_code=200, content=_content)


# Get Stats
@app.get("/logs_stats")
def logs(*,
    company_id:str=Query(...), # all / company_id
    # status_filter:str=Query(None), # success, all, failure, issue
    # service_filter:str=Query(None), # face_comparison , all , passive_liveness
    start_datetime:datetime.datetime = Query(...),
    end_datetime:datetime.datetime = Query(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request
):
    with database_client.Session() as session:
        query = session.query(
            ServiceMaster.service_name,
            StatusMaster.status,
            # NFaceLogs.service_id,
            # NFaceLogs.service_id,
            func.count().label('count')
        ).join(
           NFaceLogs,
           StatusMaster.status_id==NFaceLogs.status_id
        ).join(
           ServiceMaster,
           ServiceMaster.service_id==NFaceLogs.service_id
        )


        # Apply filters based on parameters
        if company_id != "all":
            query = query.join(Company, Company.company_id == NFaceLogs.company_id).filter(Company.public_id == company_id)

        query = query.filter(NFaceLogs.create_date >= start_datetime,
                                NFaceLogs.create_date <= end_datetime)

        # Add grouping and ordering
        # query = query.group_by(NFaceLogs.service_id, NFaceLogs.status_id,)
        query = query.group_by(ServiceMaster.service_name, StatusMaster.status,)


        if query:
            query = query.all()
            nested_dict = {}
            for outer_key, inner_key, value in query:
                if outer_key not in nested_dict:
                    nested_dict[outer_key] = {}
                nested_dict[outer_key][inner_key] = value


    _content = {"meta":{"successful":True,"error":None},"data":nested_dict}
    return JSONResponse(status_code=200, content=_content)


# Get Invoice
# Get Invoice File


# Onboard Client
# Get Stats

# CRUD Company
@app.get("/company/{company_id}")
def get_company(
    company_id:str=Path(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
):
    with database_client.Session() as session:
        query = session.query(Company)
        if company_id != "all":
            query = query.filter(Company.public_id == company_id)


        _q = []
        if query:
            query = query.all()

            for ld in query :
                _dt = ld.to_dict()
                

                banking_info = session.query(
                        CompanyBankingInfo
                    ).filter(
                        CompanyBankingInfo.company_id == _dt.get("company_id",{})
                    ).order_by(
                        CompanyBankingInfo.update_date.desc()
                    ).first()

                _dt["banking_info"] = banking_info.to_dict() if banking_info else None
                _q.append(_dt)

    _content = {"meta":{"successful":True,"error":None},"data":_q}
    return JSONResponse(status_code=200, content=_content)


@app.get("/invoice")
def get_company_invoice(
    company_id:str=Query("all"),
    status_filter:str=Query("all"), # pending, all, paid
    start_datetime:datetime.datetime = Query(...),
    end_datetime:datetime.datetime = Query(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
):
    with database_client.Session() as session:

        query = session.query(
            Invoice,
            CompanyBankingInfo.bank_type
        ).join(
            CompanyBankingInfo,
            CompanyBankingInfo.company_id==Invoice.company_id
        )


        if company_id != "all":
            query = query.join(Company, Company.company_id == Invoice.company_id).filter(Company.public_id == company_id)

        if status_filter != "all":
            sf = 1 if status_filter.upper().strip() == "PAID" else 0
            query = query.filter(Invoice.payment_status == sf)


        query = query.filter(NFaceLogs.create_date >= start_datetime,
                                NFaceLogs.create_date <= end_datetime)


        query = query.all()
        if query:
            query = [ {** q[0].to_dict(), "bank_type":q[-1]} for q in query ]

    _content = {"meta":{"successful":True,"error":None},"data":query}
    return JSONResponse(status_code=200, content=_content)
    
@app.get("/invoice_stats")
def get_company_invoice(
    company_id:str=Query("all"),
    start_datetime:datetime.datetime = Query(...),
    end_datetime:datetime.datetime = Query(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
):
    with database_client.Session() as session:

        # Perform the query using SQLAlchemy
        query = session.query(
            Invoice.payment_status,
            func.count(Invoice.payment_status).label('count'),
            func.sum(Invoice.amount).label('total_amount')
        )

        if company_id != "all":
            query = query.join(Company, Company.company_id == Invoice.company_id).filter(Company.public_id == company_id)


        query = query.filter(NFaceLogs.create_date >= start_datetime,
                                NFaceLogs.create_date <= end_datetime)

        query = query.group_by(Invoice.payment_status)

        query = query.all()
        if query:
            nested_dict = {}
            for _status, _count, _amount in query:
                _status_name = "PAID" if _status == 1 else "PENDING"
                nested_dict[_status_name] = {}
                nested_dict[_status_name]["total_count"] = _count
                nested_dict[_status_name]["total_amount"] = _amount


    _content = {"meta":{"successful":True,"error":None},"data":nested_dict}
    return JSONResponse(status_code=200, content=_content)
    



# @app.get("/invoice/file/{invoice_id}")
# def get_company_invoice(
#     invoice_id:str=Path(...),
#     decoded_token:dict = Depends(decodeJwtTokenDependancy),
# ):
#     with database_client.Session() as session:

#         query = session.query(
#             Invoice,
#             CompanyBankingInfo.bank_type
#         ).join(
#             CompanyBankingInfo,
#             CompanyBankingInfo.company_id==Invoice.company_id
#         )


# CRUD Employee
# CRUD Billing






from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(status_code=exc.status_code, content=exc.detail)


if __name__=="__main__":
    import uvicorn
    uvicorn.run(app,host="0.0.0.0",port=3000)