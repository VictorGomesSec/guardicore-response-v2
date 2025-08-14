import datetime
from typing import Generator

from sqlalchemy import update, inspect, func

from lumudblib.models.models import (
    IncidentModel,
    IoCModel,
    IncidentStatusEnum,
    IoCTypeEnum,
    CompanyModel,
)


class BaseCRUD:
    def __init__(self, db_session):
        self.db = db_session
        self.model = None

    @staticmethod
    def obj_as_dict(model_obj):
        """
        convert object to dict datatype from  sqlalchemy format to native python datatype
        :param model_obj:
        :return:
        """
        return {
            c.key: getattr(model_obj, c.key)
            for c in inspect(model_obj).mapper.column_attrs
        }

    def get_one(self, _id):
        obj = self.db.query(self.model).where(self.model.id == _id).one_or_none()
        return obj

    def get_all(self, offset=0, limit=1000):
        objs = (
            self.db.query(self.model)
            .order_by(self.model.created.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return objs

    def get_first(self):
        obj = self.db.query(self.model).first()
        return obj

    def create_one(self, **kwargs):
        obj_dict = {}
        for key, value in kwargs.items():
            if value is None:
                continue
            obj_dict[key] = value

        db_obj = self.model(**obj_dict)

        self.db.add(db_obj)
        self.db.commit()
        self.db.refresh(db_obj)

        return db_obj

    def update_one(self, _id, not_modifiable_files, **kwargs):
        obj_dict = {}
        for key, value in kwargs.items():
            if value is None or key in not_modifiable_files:
                continue
            obj_dict[key] = value

        result = self.db.execute(
            update(self.model).where(self.model.id == _id).values(**obj_dict)
        )
        self.db.commit()
        if result.rowcount:
            return self.get_one(_id)
        return False

    def update_many(self, list_id, not_modifiable_files, **kwargs):
        result = []
        for _id in list_id:
            result.append((_id, self.update_one(_id, not_modifiable_files, **kwargs)))
        return result

    def delete_one(self, _id):
        db_obj = self.get_one(_id)
        if db_obj is None:
            return False
        self.db.delete(db_obj)
        self.db.commit()
        return True

    def delete_many(self, list_id):
        result = []
        for _id in list_id:
            result.append((_id, self.delete_one(_id)))
        return result

    def disable_one(self, _id):
        db_obj = self.get_one(_id)
        if db_obj is None:
            return None
        db_obj.active = False
        self.db.commit()
        self.db.refresh(db_obj)
        return db_obj

    def enable_one(self, _id):
        db_obj = self.get_one(_id)
        if db_obj is None:
            return None
        db_obj.active = True
        self.db.commit()
        self.db.refresh(db_obj)
        return db_obj

    def disable_many(self, list_id):
        result = []
        for _id in list_id:
            result.append((_id, self.disable_one(_id)))
        return result

    def enable_many(self, list_id):
        result = []
        for _id in list_id:
            result.append((_id, self.enable_one(_id)))
        return result


class CompanyCRUD(BaseCRUD):
    def __init__(self, db_session):
        super().__init__(db_session)
        self.model = CompanyModel

    def create_update(self, **kwargs) -> bool | None | CompanyModel:
        if not (_id := kwargs.get("id")):
            return False
        if not self.get_one(_id):
            return self.create_one(**kwargs)
        return self.update_one(
            _id, not_modifiable_files=["id", "created", "active"], **kwargs
        )

    def get_incidents(self, _id) -> Generator[IncidentModel, None, None] | None:
        if obj := self.get_one(_id):
            yield from obj.incidents

    def get_inc_ioc_raw(self, _id) -> Generator[IoCModel, None, None] | None:
        if obj := self.get_one(_id):
            for inc in obj.incidents:
                yield from inc.iocs

    def get_inc_not_muted_ioc(self, _id) -> Generator[IoCModel, None, None] | None:
        if obj := self.get_one(_id):
            for inc in obj.incidents:
                if inc.status.value != IncidentStatusEnum.muted.value:
                    yield from inc.iocs

    def get_inc_not_muted_ioc_sql(self, _id: "UUID", _from: "datetime.datetime"):
        """
        Collects IOCs related to the latest non-muted incident.

        It builds a subquery to collect the latest incidents grouped per adversary.
        Later, it removes the muted incidents to finally join this result with the related IOCs

        Args:
            _id: (UUID) Company ID
            _from: (datetime.datetime) Last contact filter

        Returns:
            Query results
        """
        # This subquery collects the latest contact recorded per adversary by company
        query_latest_contacts = (
            self.db.query(
                CompanyModel.id.label("companyId"),
                IncidentModel.id.label("incidentId"),
                IncidentModel.status.label("incidentStatus"),
            )
            .join(IncidentModel.company)
            .where(CompanyModel.id == _id)
            .where(IncidentModel.lastContact >= _from)
            .group_by(IncidentModel.adversaryId)
            .having(IncidentModel.timestamp == func.max(IncidentModel.timestamp))
            .subquery()
        )

        # Now, let's collect the non muted latest contact from the previous query
        query_nonmuted_latest_contacts = (
            self.db.query(query_latest_contacts.c.incidentId)
            .where(query_latest_contacts.c.incidentStatus != IncidentStatusEnum.muted)
            .subquery()
        )

        # Finally, let's build the final query
        query = self.db.query(IoCModel).join(
            query_nonmuted_latest_contacts,
            query_nonmuted_latest_contacts.c.incidentId == IoCModel.incident_id,
        )

        # Time to return the results
        return query.all()

    def get_inc_not_muted_ioc_sql_limit_by_type(
        self, _id, _from, _type: IoCTypeEnum, limit=1000
    ):
        # This subquery collects the latest contact recorded per adversary by company
        query_latest_contacts = (
            self.db.query(
                CompanyModel.id.label("companyId"),
                IncidentModel.id.label("incidentId"),
                IncidentModel.status.label("incidentStatus"),
            )
            .join(IncidentModel.company)
            .where(CompanyModel.id == _id)
            .where(IncidentModel.lastContact >= _from)
            .group_by(IncidentModel.adversaryId)
            .having(IncidentModel.timestamp == func.max(IncidentModel.timestamp))
            .subquery()
        )

        # Now, let's collect the non muted latest contact from the previous query
        query_nonmuted_latest_contacts = (
            self.db.query(query_latest_contacts.c.incidentId)
            .where(query_latest_contacts.c.incidentStatus != IncidentStatusEnum.muted)
            .subquery()
        )

        # Finally, let's build the final query
        query = (
            self.db.query(IoCModel)
            .join(
                query_nonmuted_latest_contacts,
                query_nonmuted_latest_contacts.c.incidentId == IoCModel.incident_id,
            )
            .join(IncidentModel)
            .where(IoCModel.type == _type)
            .order_by(IncidentModel.lastContact.desc())
            .limit(limit)
        )

        # Time to return the results
        return query.all()

    def del_inc_and_ioc(self, _id):
        obj: CompanyModel = self.get_one(_id)
        if obj:
            for inc in obj.incidents:
                for ioc in inc.iocs:
                    self.db.delete(ioc)
                self.db.delete(inc)
            self.db.delete(obj)
            self.db.commit()

    def get_inc_adversary_repeated_mute_close(self, _id, _from):
        """
        SQL -> SELECT adversaryId FROM incidents WHERE status != 'open' GROUP By adversaryId HAVING count(adversaryId) > 1
        :param _id:
        :param _from:
        :return: list of adversaries repeated twice and more
        [('activity.lumu.io',), ('epkkgkpeew.com',), ('fat-beach-huge.on-fleek.app',)]
        ['activity.lumu.io','epkkgkpeew.com','fat-beach-huge.on-fleek.app']
        """
        result_1 = (
            self.db.query(IncidentModel.adversaryId.distinct())
            .where(IncidentModel.companyId == _id)
            .where(IncidentModel.status == "muted")
            .where(IncidentModel.lastContact >= _from)
            .all()
        )
        mutes = set(r[0] for r in result_1)

        result = (
            self.db.query(IncidentModel.adversaryId.distinct())
            .where(IncidentModel.companyId == _id)
            .where(IncidentModel.status == "closed")
            .where(IncidentModel.lastContact >= _from)
            .all()
        )
        closes = set(r[0] for r in result)

        return list(mutes.intersection(closes))


class IncidentCRUD(BaseCRUD):
    def __init__(self, db_session):
        super().__init__(db_session)
        self.model = IncidentModel

    def get_iocs(self, _id) -> list[IoCModel] | None:
        if obj := self.get_one(_id):
            return obj.iocs
        return None

    def get_all(self, offset=0, limit=1000) -> list[IncidentModel] | None:
        objs = (
            self.db.query(self.model)
            .order_by(self.model.created.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        yield from objs
        while objs:
            offset += limit
            objs = (
                self.db.query(self.model)
                .order_by(self.model.created.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            yield from objs

    def get_open(self, offset=0, limit=1000) -> list[IncidentModel] | None:
        status = IncidentStatusEnum.open
        objs = (
            self.db.query(self.model)
            .where(self.model.status == status)
            .order_by(self.model.created.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        yield from objs
        while objs:
            offset += limit
            objs = (
                self.db.query(self.model)
                .where(self.model.status == status)
                .order_by(self.model.created.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            yield from objs

    def get_muted(self, offset=0, limit=1000) -> list[IncidentModel] | None:
        status = IncidentStatusEnum.muted
        objs = (
            self.db.query(self.model)
            .where(self.model.status == status)
            .order_by(self.model.created.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        yield from objs
        while objs:
            offset += limit
            objs = (
                self.db.query(self.model)
                .where(self.model.status == status)
                .order_by(self.model.created.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            yield from objs

    def get_closed(self, offset=0, limit=1000) -> list[IncidentModel] | None:
        status = IncidentStatusEnum.closed
        objs = (
            self.db.query(self.model)
            .where(self.model.status == status)
            .order_by(self.model.created.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        yield from objs
        while objs:
            offset += limit
            objs = (
                self.db.query(self.model)
                .where(self.model.status == status)
                .order_by(self.model.created.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            yield from objs

    def create_update(self, **kwargs) -> bool | None | IncidentModel:
        if not (_id := kwargs.get("id")):
            return False
        if not self.get_one(_id):
            return self.create_one(**kwargs)
        return self.update_one(
            _id, not_modifiable_files=["id", "created", "active"], **kwargs
        )

    def delete_expired_items(self, expired_date: datetime.datetime):
        objs: list[IncidentModel] = (
            self.db.query(self.model)
            .where(self.model.lastContact <= expired_date)
            .all()
        )
        for obj in objs:
            for ioc in obj.iocs:
                self.db.delete(ioc)
            self.db.delete(obj)
            self.db.commit()


class IoCCRUD(BaseCRUD):
    def __init__(self, db_session):
        super().__init__(db_session)
        self.model = IoCModel

    def get_by_value(self, value, incident_id=None):
        obj = (
            self.db.query(self.model)
            .where(self.model.value == value)
            .where(self.model.incident_id == incident_id)
            .one_or_none()
        )
        return obj

    def get_all_active(self, offset=0, limit=100):
        objs = (
            self.db.query(self.model)
            .where(self.model.active == True)
            .order_by(self.model.created.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return objs

    def get_all_hash(self, offset=0, limit=1000) -> Generator[IoCModel, None, None]:
        ioc_type = IoCTypeEnum.hash
        objs = (
            self.db.query(self.model)
            .where(self.model.type == ioc_type)
            .order_by(self.model.created.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        yield from objs
        while objs:
            offset += limit
            objs = (
                self.db.query(self.model)
                .where(self.model.type == ioc_type)
                .order_by(self.model.created.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            yield from objs

    def get_all_domain(self, offset=0, limit=1000) -> Generator[IoCModel, None, None]:
        ioc_type = IoCTypeEnum.domain
        objs = (
            self.db.query(self.model)
            .where(self.model.type == ioc_type)
            .order_by(self.model.created.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        yield from objs
        while objs:
            offset += limit
            objs = (
                self.db.query(self.model)
                .where(self.model.type == ioc_type)
                .order_by(self.model.created.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            yield from objs

    def get_all_url(self, offset=0, limit=1000) -> Generator[IoCModel, None, None]:
        ioc_type = IoCTypeEnum.url
        objs = (
            self.db.query(self.model)
            .where(self.model.type == ioc_type)
            .order_by(self.model.created.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        yield from objs
        while objs:
            offset += limit
            objs = (
                self.db.query(self.model)
                .where(self.model.type == ioc_type)
                .order_by(self.model.created.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            yield from objs

    def get_all_total_url(self, offset=0, limit=100):
        """

        :param offset:
        :param limit:
        :return: list of dict
        """
        result = []
        objs = self.get_all_url(offset, limit)

        result.extend([self.obj_as_dict(obj) for obj in objs])
        i = 1
        while objs:
            offset = limit * i

            objs = self.get_all_url(offset, limit)
            result.extend([self.obj_as_dict(obj) for obj in objs])

            i += 1
        return result

    def get_all_ip(self, offset=0, limit=1000) -> Generator[IoCModel, None, None]:
        ioc_type = IoCTypeEnum.ip
        objs = (
            self.db.query(self.model)
            .where(self.model.type == ioc_type)
            .order_by(self.model.created.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        yield from objs
        while objs:
            offset += limit
            objs = (
                self.db.query(self.model)
                .where(self.model.type == ioc_type)
                .order_by(self.model.created.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            yield from objs

    def get_inc_not_muted_ioc_sql(self, _from):
        return (
            self.db.query(IoCModel)
            .join(IoCModel.incident)
            .where(IncidentModel.status != IncidentStatusEnum.muted)
            .where(IncidentModel.lastContact >= _from)
            .all()
        )

    def delete_one(self, ioc, incident_id=None):
        if ioc_db := self.get_by_value(value=ioc, incident_id=incident_id):
            return super().delete_one(ioc_db.id)
        return None

    def safe_create_one(self, **kwargs):
        """
        assuming a successful IoC upload into Local DB, then,it has to update the record in the local DB
        and write or overwrite the current IoC
        :param kwargs:
        :return:
        """
        ioc_value = kwargs["value"]
        incident_id = kwargs["incident_id"]
        ioc_db = self.get_by_value(value=ioc_value, incident_id=incident_id)
        if ioc_db is None:
            ioc_db = self.create_one(**kwargs)
        _id = ioc_db.id
        self.enable_one(_id)
        return ioc_db

    def safe_delete_one(self, **kwargs):
        """
        assuming a successful IoC upload into Local DB, then,it has to update the record in the local DB
        and soft delete the old IoC
        :param kwargs:
        :return:
        """
        ioc_value = kwargs["value"]
        incident_id = kwargs["incident_id"]
        ioc_db = self.get_by_value(value=ioc_value, incident_id=incident_id)
        if ioc_db is None:
            ioc_db = self.create_one(**kwargs)
        _id = ioc_db.id
        self.disable_one(_id)
        return ioc_db

    def safe_create_many(self, list_ioc):
        """

        :param: list_ioc: list of dictionaries
        :return:
        """
        result = []
        for record_ioc in list_ioc:
            result.append((record_ioc["value"], self.safe_create_one(**record_ioc)))
        return result

    def safe_delete_many(self, list_ioc):
        """

        :param: list_ioc: list of dictionaries
        :return:
        """
        result = []
        for record_ioc in list_ioc:
            result.append((record_ioc["value"], self.safe_delete_one(**record_ioc)))
        return result
