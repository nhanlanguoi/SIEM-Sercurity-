function getAggregations(response) {
  return response?.aggregations || response?.body?.aggregations || {};
}

function isIndexNotFound(error) {
  return error?.meta?.statusCode === 404 || error?.statusCode === 404;
}

module.exports = {
  getAggregations,
  isIndexNotFound
};
