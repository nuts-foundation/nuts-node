package usecase

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/usecase/log"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type httpClient struct {
	requestDoer core.HTTPRequestDoer
}

func (c httpClient) add(listEndpoint string, presentation vc.VerifiablePresentation) error {
	requestURL, err := url.Parse(listEndpoint)
	if err != nil {
		// Would be very weird
		return err
	}
	httpRequest, err := http.NewRequest(http.MethodPost, requestURL.String(), bytes.NewReader([]byte(presentation.Raw())))
	if err != nil {
		return err
	}
	httpResponse, err := c.requestDoer.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("failed to add presentation to list '%s': %w", listEndpoint, err)
	}
	if httpResponse.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to add presentation to list '%s': status %s", listEndpoint, httpResponse.Status)
	}
	return nil
}

func (c httpClient) get(listEndpoint string, timestamp Timestamp) ([]vc.VerifiablePresentation, Timestamp, error) {
	requestURL, err := url.Parse(listEndpoint)
	if err != nil {
		// Would be very weird
		return nil, 0, err
	}
	requestURL.Query().Add("timestamp", fmt.Sprintf("%d", timestamp))
	httpRequest, err := http.NewRequest(http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	httpResponse, err := c.requestDoer.Do(httpRequest)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get list '%s': %w", listEndpoint, err)
	}
	if httpResponse.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("failed to get list '%s': status %s", listEndpoint, httpResponse.Status)
	}
	data, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed read list response from '%s': %w", listEndpoint, err)
	}
	type listResponse struct {
		Entries   []vc.VerifiablePresentation `json:"entries"`
		Timestamp Timestamp                   `json:"timestamp"`
	}
	var response listResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, 0, fmt.Errorf("failed to parse list response from '%s': %w", listEndpoint, err)
	}
	return response.Entries, response.Timestamp, nil
}

func newClient(definitions map[string]Definition, refreshInterval time.Duration) *client {
	result := &client{
		definitions: definitions,
	}
	result.startRefresh(refreshInterval)
	return result
}

type client struct {
	definitions         map[string]Definition
	timestamps          map[string]Timestamp
	presentations       map[string][]vc.VerifiablePresentation
	refreshTicker       *time.Ticker
	refreshTickerWaiter sync.WaitGroup
}

func (c *client) stop() {
	c.refreshTicker.Stop()
	log.Logger().Debug("Waiting for refresh ticker to stop")
	c.refreshTickerWaiter.Wait()
}

func (c *client) startRefresh(interval time.Duration) {
	c.refreshTicker = time.NewTicker(interval)
	c.refreshTickerWaiter = sync.WaitGroup{}
	c.refreshTickerWaiter.Add(1)
	go func(ticker *time.Ticker, waiter *sync.WaitGroup) {
		defer waiter.Done()
		for range ticker.C {
			for definitionID := range c.definitions {
				if err := c.refresh(definitionID); err != nil {
					log.Logger().Errorf("Failed to refresh definition '%s': %s", definitionID, err)
				}
			}
		}
	}(c.refreshTicker, &c.refreshTickerWaiter)
}

func (c *client) refresh(definitionID string) error {
	definition := c.definitions[definitionID]
	presentations, newTimestamp, err := httpClient{requestDoer: http.DefaultClient}.get(definition.Endpoint, c.timestamps[definitionID])
	if err != nil {
		return err
	}
	c.timestamps[definitionID] = newTimestamp
	c.presentations[definitionID] = append(c.presentations[definitionID], presentations...)
	return nil
}
