# Country map geometry

`countries.json` contains simplified SVG country paths generated from Natural Earth's 1:110m admin 0 country polygons. The map uses an equirectangular projection, excludes Antarctica, and combines regions with the same country code. Small territories may be absent at this scale.

Source: https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/ne_110m_admin_0_countries.geojson

License: public domain. https://www.naturalearthdata.com/about/terms-of-use/

Country geometry is bundled with the frontend. Viewing the map makes no requests to an external map provider. Event country counts come from the selected VPS security database, independently of the map geometry.
