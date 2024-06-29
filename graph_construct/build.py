from py2neo import Graph, Node, Relationship, NodeMatcher, RelationshipMatcher, database
from py2neo import cypher
import pandas as pd
import numpy as np


class ZGraph:
    def __init__(self, username, password):
        # username: neo4j   password:avs01046
        self.database = Graph('http://localhost:7474', auth=(username, password))

    def CreateNode(self, labels, attr):
        re_value = self.MatchSingleNode(labels, attr)
        if re_value is None:
            newnode = Node(labels)
            for key, value in attr.items():
                # Neo4j node's value only support string format
                if not isinstance(value, str):
                    value = str(value)
                newnode[key] = value
            result = self.database.create(newnode)
            return result
        return -1

    def MatchSingleNode(self, labels, attr):
        matcher = NodeMatcher(self.database)
        matching = ""
        count = 0
        for key in attr:
            if count != 0:
                matching += " and "
            matching += "_." + str(key) + "=\'" + str(attr[key]) + "\'"
            count += 1
        result = matcher.match(labels).where(matching).first()
        return result

    def MatchMultipleNode(self, labels, attr):
        matcher = NodeMatcher(self.database)
        matching = ""
        for index, key in enumerate(attr):
            if index != 0:
                matching += " and "
            matching += "_." + str(key) + "=\'" + str(attr[key]) + "\'"
        result = matcher.match(labels).where(matching).all()
        return result

    def UpdateRelationship(self, node1, node2, relation_label, relation_attr, update_value):
        relmatcher = RelationshipMatcher(self.database)
        relationship = relmatcher.match(nodes={node1, node2}, r_type=relation_label).first()
        if relationship is None:
            relation_attr["Action_Sequence"].append(update_value)
            self.CreateRelationship(node1, node2, relation_label, relation_attr)
        else:
            relationship["Action_Sequence"].append(update_value)
            self.database.push(relationship)

    def CreateRelationship(self, node1, node2, relation_label, relation_attr):
        if node1 is None or node2 is None:
            return False
        relationship = Relationship.type(relation_label)
        events = relationship(node1, node2)

        for key, value in relation_attr.items():
            events[key] = value

        try:
            result = self.database.create(events)
            return result
        except Exception as e:
            print(relation_attr)
            raise e









