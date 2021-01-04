﻿using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using RESTFunctions.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace RESTFunctions.Services
{
    public class GraphOpenExtensions
    {
        private static readonly string propName = "MT.Props";
        public GraphOpenExtensions(Graph graph, ILogger<GraphOpenExtensions> logger)
        {
            _graph = graph;
            _logger = logger;
        }
        Graph _graph;
        ILogger<GraphOpenExtensions> _logger;

        public async Task<bool> CreateAsync(TenantDetails tenant)
        {
            var http = await _graph.GetClientAsync();
            var resp = await http.PostAsync(
                $"{Graph.BaseUrl}groups/{tenant.id}/extensions",
                new StringContent(ToJson(tenant).ToString(), System.Text.Encoding.UTF8, "application/json"));
            return resp.IsSuccessStatusCode;
        }
        public async Task<TenantDetails> GetAsync(TenantDetails tenant)
        {
            var http = await _graph.GetClientAsync();
            var resp = await http.SendAsync(new HttpRequestMessage(HttpMethod.Get, $"{Graph.BaseUrl}groups/{tenant.id}/extensions/{propName}/"));
            if (resp.IsSuccessStatusCode)
            {
                var json = await resp.Content.ReadAsStringAsync();
                var result = JObject.Parse(json);
                tenant.requireMFA = result["requireMFA"]?.Value<bool>();
                tenant.identityProvider = result["identityProvider"]?.Value<string>();
                tenant.directoryId = result["tenantId"]?.Value<string>();
                tenant.allowSameIssuerMembers = result["allowSameIssuerMembers"]?.Value<bool>();
            }
            return tenant;
        }
        public async Task<bool> UpdateAsync(TenantDetails tenant)
        {
            var http = await _graph.GetClientAsync();
            var req = new HttpRequestMessage(HttpMethod.Get, $"{Graph.BaseUrl}groups/{tenant.id}/extensions/{propName}");
            var resp = await http.SendAsync(req);
            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
                return await CreateAsync(tenant);
            var json = ToJson(tenant);
            resp = await http.PatchAsync(
                $"{Graph.BaseUrl}groups/{tenant.id}/extensions/{propName}",
                new StringContent(ToJson(tenant, false).ToString(), System.Text.Encoding.UTF8, "application/json"));
            return resp.IsSuccessStatusCode;
        }
        private JObject ToJson(TenantDetails tenant, bool withHeader = true)
        {
            var ext = new
            {
                requireMFA = false,
                identityProvider = tenant.identityProvider,
                tenantId = tenant.directoryId,
                allowSameIssuerMembers = tenant.allowSameIssuerMembers,
            };
            var extStr = JsonConvert.SerializeObject(ext);
            var extJson = JObject.Parse(extStr);
            if (withHeader)
            {
                extJson.AddFirst(new JProperty("extensionName", propName));
                extJson.AddFirst(new JProperty("@odata.type", "#microsoft.graph.openTypeExtension"));
            }
            return extJson;
        }
    }
}
